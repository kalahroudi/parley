// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/caller"
	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/localsock"
)

// fakeDaemon answers send_task and get_task from a script and remembers what it was asked.
type fakeDaemon struct {
	mu     sync.Mutex
	sent   caller.SendParams
	gets   []caller.GetParams
	views  []caller.View // answers to get_task, in order; the last repeats
	sendFn func(p caller.SendParams) (localsock.Response, error)
	getFn  func(n int, p caller.GetParams) (localsock.Response, error)
	clock  time.Time
	tick   time.Duration // how far each get_task moves the clock
	pauses int           // how often the command waited between attempts
}

func ok(v any) localsock.Response {
	b, _ := json.Marshal(v)
	return localsock.Response{OK: true, Result: b}
}

func (f *fakeDaemon) call(_ context.Context, method string, params any) (localsock.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch method {
	case "send_task":
		f.sent = params.(caller.SendParams)
		if f.sendFn != nil {
			return f.sendFn(f.sent)
		}
		return ok(caller.View{ID: "00ff", Target: f.sent.Agent, State: caller.Submitted}), nil
	case "get_task":
		p := params.(caller.GetParams)
		f.gets = append(f.gets, p)
		f.clock = f.clock.Add(f.tick)
		if f.getFn != nil {
			return f.getFn(len(f.gets), p)
		}
		i := min(len(f.gets)-1, len(f.views)-1)
		v := f.views[i]
		if v.State == caller.Completed && v.Content == "ECHO" {
			v.Content = daemon.TestBotPrefix + f.sent.Text
		}
		return ok(v), nil
	}
	return localsock.Response{}, errors.New("unexpected " + method)
}

func (f *fakeDaemon) session(out, errw *bytes.Buffer) *session {
	return &session{call: f.call, out: out, errw: errw, rand: bytes.NewReader(bytes.Repeat([]byte{0xab}, 64)),
		now:   func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.clock },
		sleep: func(d time.Duration) { f.mu.Lock(); f.clock = f.clock.Add(d); f.pauses++; f.mu.Unlock() }}
}

func runTest(f *fakeDaemon, args ...string) (int, string, string) {
	var o, e bytes.Buffer
	if f.clock.IsZero() {
		f.clock = time.Unix(1_700_000_000, 0)
	}
	code := f.session(&o, &e).selfTest(context.Background(), args)
	return code, o.String(), e.String()
}

func TestSelfTestPassesOnTheExpectedEcho(t *testing.T) {
	f := &fakeDaemon{views: []caller.View{{ID: "00ff", State: caller.Working}, {ID: "00ff", State: caller.Completed, Kind: caller.KindResult, Content: "ECHO"}}, tick: 40 * time.Millisecond}
	code, out, errw := runTest(f, "-to", "dev2")
	if code != 0 || !strings.Contains(out, "PASS") || !strings.Contains(out, "80ms") || errw != "" {
		t.Fatalf("%d %q %q", code, out, errw)
	}
	// A fresh random text from the entropy source, sent to the named device, with the timeout as its expiry.
	if f.sent.Agent != "dev2" || f.sent.Text != "parley-test "+strings.Repeat("ab", 16) || f.sent.ExpirySeconds != 30 || f.sent.TaskID != "" {
		t.Fatalf("sent %+v", f.sent)
	}
	if len(f.gets) != 2 || f.gets[0].TaskID != "00ff" || f.gets[0].WaitSeconds != 20 {
		t.Fatalf("gets %+v", f.gets) // waits in slices the daemon allows
	}
	if strings.Contains(out, f.sent.Text) {
		t.Error("the test text is echoed to the terminal")
	}
}

func TestSelfTestFailsWhenTheAnswerIsNotTheEcho(t *testing.T) {
	for name, v := range map[string]caller.View{
		"another answer":  {State: caller.Completed, Kind: caller.KindResult, Content: "something else"},
		"a status":        {State: caller.Completed, Kind: caller.KindStatus, Content: "ECHO"},
		"no content":      {State: caller.Completed},
		"a failure":       {State: caller.Failed, Reason: caller.ReasonOffline},
		"a rejection":     {State: caller.Rejected, Reason: caller.ReasonNotAllowed},
		"a refusal":       {State: caller.Failed, Reason: caller.ReasonRefused},
		"unknown device":  {State: caller.Failed, Reason: caller.ReasonGone},
		"not ready":       {State: caller.Failed, Reason: caller.ReasonNotReady},
		"expired":         {State: caller.Failed, Reason: caller.ReasonExpired},
		"canceled":        {State: caller.Canceled},
		"weird reason":    {State: caller.Failed, Reason: "Bad Reason!"},
		"another message": {State: caller.Failed, Reason: caller.ReasonSendFailed},
	} {
		code, out, errw := runTest(&fakeDaemon{views: []caller.View{v}}, "-to", "dev2")
		if code != 1 || strings.Contains(out, "PASS") || !strings.Contains(errw, "FAIL") {
			t.Errorf("%s: %d %q %q", name, code, out, errw)
		}
		if strings.Contains(errw, "Bad Reason!") {
			t.Errorf("%s: a text from outside reached the terminal: %q", name, errw)
		}
	}
	_, _, errw := runTest(&fakeDaemon{views: []caller.View{{State: caller.Failed, Reason: caller.ReasonRefused}}}, "-to", "dev2")
	if !strings.Contains(errw, "owner") {
		t.Errorf("no hint: %q", errw)
	}
}

func TestSelfTestExplainsDaemonErrors(t *testing.T) {
	refuse := func(code string) func(caller.SendParams) (localsock.Response, error) {
		return func(caller.SendParams) (localsock.Response, error) { return localsock.Response{Error: code}, nil }
	}
	for name, tc := range map[string]struct {
		f    *fakeDaemon
		want string
	}{
		"daemon down":   {&fakeDaemon{sendFn: func(caller.SendParams) (localsock.Response, error) { return localsock.Response{}, errors.New("dial") }}, "not running"},
		"not enrolled":  {&fakeDaemon{sendFn: refuse(caller.CodeNotReady)}, "enrolled"},
		"bad device id": {&fakeDaemon{sendFn: refuse(caller.CodeBadParams)}, "not a device id"},
		"rate limited":  {&fakeDaemon{sendFn: refuse(caller.CodeRateLimit)}, "rate_limited"},
		"hostile code":  {&fakeDaemon{sendFn: refuse("SECRET text")}, "internal"},
		"garbled send": {&fakeDaemon{sendFn: func(caller.SendParams) (localsock.Response, error) {
			return localsock.Response{OK: true, Result: []byte("{")}, nil
		}}, "internal"},
		"daemon lost": {&fakeDaemon{getFn: func(int, caller.GetParams) (localsock.Response, error) {
			return localsock.Response{}, errors.New("eof")
		}}, "not running"},
		"task forgotten": {&fakeDaemon{getFn: func(int, caller.GetParams) (localsock.Response, error) {
			return localsock.Response{Error: caller.CodeNotFound}, nil
		}}, "not_found"},
	} {
		code, out, errw := runTest(tc.f, "-to", "dev2")
		if code != 1 || strings.Contains(out, "PASS") || !strings.Contains(errw, tc.want) || strings.Contains(errw, "SECRET") {
			t.Errorf("%s: %d %q %q", name, code, out, errw)
		}
	}
}

func TestSelfTestGivesUpWhenNoAnswerComes(t *testing.T) {
	f := &fakeDaemon{views: []caller.View{{ID: "00ff", State: caller.Working}}, tick: 20 * time.Second}
	code, _, errw := runTest(f, "-to", "dev2", "-timeout", "45s")
	if code != 1 || !strings.Contains(errw, "no answer in time") {
		t.Fatalf("%d %q", code, errw)
	}
	// Each wait is what is left, in whole seconds and never more than the daemon allows.
	if len(f.gets) != 3 || f.gets[0].WaitSeconds != 20 || f.gets[1].WaitSeconds != 20 || f.gets[2].WaitSeconds != 7 {
		t.Fatalf("waits %+v", f.gets)
	}
	// An interrupted test stops at once.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var o, e bytes.Buffer
	g := &fakeDaemon{views: []caller.View{{State: caller.Working}}, clock: time.Unix(1_700_000_000, 0)}
	if code := g.session(&o, &e).selfTest(ctx, []string{"-to", "dev2"}); code != 1 || len(g.gets) != 0 {
		t.Fatalf("%d, %d gets", code, len(g.gets))
	}
}

func TestSelfTestUsage(t *testing.T) {
	for name, args := range map[string][]string{
		"no target":      {},
		"empty target":   {"-to", ""},
		"extra argument": {"-to", "d", "x"},
		"unknown flag":   {"-nope"},
		"too short":      {"-to", "d", "-timeout", "4s"},
		"too long":       {"-to", "d", "-timeout", "16m"},
		"fractional":     {"-to", "d", "-timeout", "1500ms"},
		"negative":       {"-to", "d", "-timeout", "-5s"},
	} {
		f := &fakeDaemon{}
		if code, _, errw := runTest(f, args...); code != 2 || errw == "" || f.sent.Agent != "" {
			t.Errorf("%s: %d %q (sent %+v)", name, code, errw, f.sent)
		}
	}
	// The longest and shortest allowed.
	for _, d := range []string{"5s", "15m"} {
		f := &fakeDaemon{views: []caller.View{{State: caller.Completed, Kind: caller.KindResult, Content: "ECHO"}}}
		if code, _, errw := runTest(f, "-to", "d", "-timeout", d); code != 0 {
			t.Errorf("%s: %d %q", d, code, errw)
		}
	}
}

func TestSelfTestNeedsRandomness(t *testing.T) {
	var o, e bytes.Buffer
	s := (&fakeDaemon{}).session(&o, &e)
	s.rand = strings.NewReader("short")
	if code := s.selfTest(context.Background(), []string{"-to", "d"}); code != 1 || !strings.Contains(e.String(), "randomness") {
		t.Fatalf("%d %q", code, e.String())
	}
}

// With no seams set the command uses the real entropy source and clock (and fails only because no daemon answers).
func TestSelfTestDefaults(t *testing.T) {
	var o, e bytes.Buffer
	s := &session{out: &o, errw: &e, call: func(context.Context, string, any) (localsock.Response, error) {
		return localsock.Response{}, errors.New("down")
	}}
	if code := s.selfTest(context.Background(), []string{"-to", "d"}); code != 1 || !strings.Contains(e.String(), "not running") {
		t.Fatalf("%d %q", code, e.String())
	}
}

// The command is reachable from the command line and talks to the daemon's socket like the others.
func TestTestCommandIsWiredToTheSocket(t *testing.T) {
	home := daemonWith(t, map[string]localsock.Method{})
	code, out, errw := run(t, home, "", "test", "-to", "dev2")
	if code != 1 || out != "" && strings.Contains(out, "PASS") || !strings.Contains(errw, "FAIL") {
		t.Fatalf("%d %q %q", code, out, errw)
	}
}

// A daemon that has just started fails the first send with not_ready (no revocation list yet): the test sends
// again for a short while, with the time left as the task's expiry, and passes once the daemon is ready.
func TestSelfTestRetriesWhileTheDaemonStarts(t *testing.T) {
	f := &fakeDaemon{views: []caller.View{{State: caller.Failed, Reason: caller.ReasonNotReady}, {State: caller.Failed, Reason: caller.ReasonNotReady}, {State: caller.Completed, Kind: caller.KindResult, Content: "ECHO"}}}
	code, out, errw := runTest(f, "-to", "dev2", "-timeout", "30s")
	if code != 0 || !strings.Contains(out, "PASS") || f.pauses != 2 || len(f.gets) != 3 {
		t.Fatalf("%d %q %q pauses=%d gets=%d", code, out, errw, f.pauses, len(f.gets))
	}
	if f.sent.ExpirySeconds != 28 { // 30s minus the two one-second pauses
		t.Fatalf("a retry must send with the time that is left: %d", f.sent.ExpirySeconds)
	}
	// A device that stays not ready is reported, with what to do, once the grace is over.
	g := &fakeDaemon{views: []caller.View{{State: caller.Failed, Reason: caller.ReasonNotReady}}, tick: 4 * time.Second}
	code, _, errw = runTest(g, "-to", "dev2", "-timeout", "60s")
	if code != 1 || !strings.Contains(errw, "Enroll this device") || g.pauses == 0 || g.pauses > 3 {
		t.Fatalf("%d %q pauses=%d", code, errw, g.pauses)
	}
	// With too little time left to try again the test ends as timed out rather than sending a task that cannot finish.
	h := &fakeDaemon{views: []caller.View{{State: caller.Failed, Reason: caller.ReasonNotReady}}, tick: 3 * time.Second}
	if code, _, errw := runTest(h, "-to", "dev2", "-timeout", "6s"); code != 1 || !strings.Contains(errw, "no answer in time") {
		t.Fatalf("%d %q", code, errw)
	}
}

// Without a sleep seam the command waits for real, and stops waiting when interrupted.
func TestSelfTestPauseWaitsOrStops(t *testing.T) {
	s := &session{}
	start := time.Now()
	s.pause(context.Background(), 20*time.Millisecond)
	if time.Since(start) < 20*time.Millisecond {
		t.Fatal("did not wait")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	s.pause(ctx, time.Hour)
	if time.Since(start) > time.Minute {
		t.Fatal("kept waiting after the context ended")
	}
}
