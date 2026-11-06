// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/localsock"
)

// recorder is a bot that counts its calls and returns the task text.
type recorder struct {
	calls atomic.Int32
}

func (r *recorder) Handle(_ context.Context, t bot.Task, _ bot.Session) ([]byte, error) {
	r.calls.Add(1)
	return append([]byte("ran: "), t.Content...), nil
}

// session records the status texts.
type session struct {
	mu       sync.Mutex
	statuses []string
	err      error
}

func (s *session) Status(_ context.Context, text []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses = append(s.statuses, string(text))
	return s.err
}
func (s *session) Ask(context.Context, []byte) ([]byte, error) { return nil, errors.New("unused") }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func id(n byte) [16]byte { return [16]byte{n} }

func task(n byte, caller, owner, content string) bot.Task {
	return bot.Task{ID: id(n), Caller: caller, Owner: owner, Content: []byte(content)}
}

type outcome struct {
	res []byte
	err error
}

// start runs Handle on its own goroutine.
func start(g *Gate, ctx context.Context, t bot.Task, s bot.Session) <-chan outcome {
	ch := make(chan outcome, 1)
	go func() {
		res, err := g.Handle(ctx, t, s)
		ch <- outcome{res, err}
	}()
	return ch
}

// waitPending blocks until n tasks wait.
func waitPending(t *testing.T, g *Gate, n int) {
	t.Helper()
	for i := 0; i < 2000; i++ {
		if len(g.List()) == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%d tasks never waited (have %d)", n, len(g.List()))
}

func get(t *testing.T, ch <-chan outcome) outcome {
	t.Helper()
	select {
	case o := <-ch:
		return o
	case <-time.After(10 * time.Second):
		t.Fatal("Handle did not return")
		return outcome{}
	}
}

func failureText(t *testing.T, err error) string {
	t.Helper()
	var f *bot.Failure
	if !errors.As(err, &f) {
		t.Fatalf("not a Failure: %v", err)
	}
	return f.Message
}

func newGate(t *testing.T, cfg Config) (*Gate, *recorder) {
	t.Helper()
	r := &recorder{}
	cfg.Bot = r
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g, r
}

func TestConstantsArePinned(t *testing.T) {
	if DefaultTimeout != 5*time.Minute || DefaultMaxPending != 16 || DefaultMaxPerCaller != 4 || MaxPreview != 512 || maxIdentity != 128 {
		t.Fatal("a limit changed")
	}
}

func TestNewValidatesAndDefaults(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrConfig) {
		t.Fatalf("no bot: %v", err)
	}
	if _, err := New(Config{Bot: &recorder{}, Mode: "sometimes"}); !errors.Is(err, ErrConfig) {
		t.Fatalf("unknown mode: %v", err)
	}
	g, _ := newGate(t, Config{})
	if g.cfg.Mode != None || g.cfg.Timeout != DefaultTimeout || g.cfg.MaxPending != DefaultMaxPending || g.cfg.MaxPerCaller != DefaultMaxPerCaller || g.cfg.Now == nil {
		t.Fatalf("defaults %+v", g.cfg)
	}
	g, _ = newGate(t, Config{Mode: Owner, Timeout: time.Second, MaxPending: 3, MaxPerCaller: 2})
	if g.cfg.Mode != Owner || g.cfg.Timeout != time.Second || g.cfg.MaxPending != 3 || g.cfg.MaxPerCaller != 2 {
		t.Fatalf("explicit values lost %+v", g.cfg)
	}
}

func TestModeNoneRunsTheBotAtOnceWithoutAskingAnyone(t *testing.T) {
	g, r := newGate(t, Config{Mode: None})
	s := &session{}
	res, err := g.Handle(context.Background(), task(1, "c", "o", "hi"), s)
	if err != nil || string(res) != "ran: hi" || r.calls.Load() != 1 || len(s.statuses) != 0 || len(g.List()) != 0 {
		t.Fatalf("res %q err %v calls %d statuses %v", res, err, r.calls.Load(), s.statuses)
	}
}

func TestOwnerModeHoldsTheTaskUntilApprovedAndThenRunsItOnce(t *testing.T) {
	g, r := newGate(t, Config{Mode: Owner})
	s := &session{}
	ch := start(g, context.Background(), task(1, "dev-1", "ann@example.com", "run the tests"), s)
	waitPending(t, g, 1)
	if r.calls.Load() != 0 {
		t.Fatal("the bot ran before approval")
	}
	if err := g.Decide(id(1), true); err != nil {
		t.Fatal(err)
	}
	o := get(t, ch)
	if o.err != nil || string(o.res) != "ran: run the tests" || r.calls.Load() != 1 {
		t.Fatalf("%q %v calls %d", o.res, o.err, r.calls.Load())
	}
	if len(s.statuses) != 1 || s.statuses[0] != TextWaiting {
		t.Fatalf("statuses %v", s.statuses)
	}
	if len(g.List()) != 0 {
		t.Fatal("still listed after the task ended")
	}
	if g.Decide(id(1), true) == nil {
		t.Fatal("approved a task that already ran")
	}
}

func TestDenialRejectsAndTheBotNeverSeesTheTask(t *testing.T) {
	g, r := newGate(t, Config{Mode: Owner})
	ch := start(g, context.Background(), task(1, "c", "o", "rm -rf"), &session{})
	waitPending(t, g, 1)
	if err := g.Decide(id(1), false); err != nil {
		t.Fatal(err)
	}
	o := get(t, ch)
	if o.res != nil || failureText(t, o.err) != TextDenied || r.calls.Load() != 0 {
		t.Fatalf("%q %v calls %d", o.res, o.err, r.calls.Load())
	}
	if strings.Contains(TextDenied, "rm") || !strings.HasPrefix(TextDenied, "rejected:") {
		t.Fatal("denial text")
	}
}

func TestNoAnswerInTimeRejects(t *testing.T) {
	g, r := newGate(t, Config{Mode: Owner, Timeout: 20 * time.Millisecond})
	ch := start(g, context.Background(), task(1, "c", "o", "x"), &session{})
	o := get(t, ch)
	if failureText(t, o.err) != TextTimedOut || r.calls.Load() != 0 || len(g.List()) != 0 {
		t.Fatalf("%v calls %d", o.err, r.calls.Load())
	}
	if g.Decide(id(1), true) == nil {
		t.Fatal("approved after the timeout")
	}
}

func TestAnApprovalPastTheDeadlineIsRefusedEvenBeforeTheTimerFires(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	g, r := newGate(t, Config{Mode: Owner, Now: c.now, Timeout: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	ch := start(g, ctx, task(1, "c", "o", "x"), &session{})
	waitPending(t, g, 1)
	c.add(time.Hour - time.Second)
	if err := g.Decide(id(1), true); err != nil { // a second before the deadline: accepted
		t.Fatal(err)
	}
	if o := get(t, ch); o.err != nil || r.calls.Load() != 1 {
		t.Fatalf("%v", o.err)
	}
	cancel()

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	ch = start(g, ctx, task(2, "c", "o", "x"), &session{})
	waitPending(t, g, 1)
	c.add(time.Hour) // exactly at the deadline: refused
	if !errors.Is(g.Decide(id(2), true), ErrNotPending) {
		t.Fatal("approved at the deadline")
	}
	cancel()
	get(t, ch)
}

func TestTheFirstDecisionStandsAndLaterOnesAreRefused(t *testing.T) {
	g, r := newGate(t, Config{Mode: Owner})
	ch := start(g, context.Background(), task(1, "c", "o", "x"), &session{})
	waitPending(t, g, 1)
	if err := g.Decide(id(1), false); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(g.Decide(id(1), true), ErrNotPending) {
		t.Fatal("approved after a denial")
	}
	if !errors.Is(g.Decide(id(1), false), ErrNotPending) {
		t.Fatal("decided twice")
	}
	if o := get(t, ch); failureText(t, o.err) != TextDenied || r.calls.Load() != 0 {
		t.Fatal("the denial did not stand")
	}
}

func TestDecidedTasksAreNotListed(t *testing.T) {
	g, _ := newGate(t, Config{Mode: Owner})
	// Hold the lock-free window between the decision and the task leaving: a stub entry decided but still present.
	g.waiting[id(9)] = &entry{id: id(9), decided: true}
	if len(g.List()) != 0 {
		t.Fatal("a decided task is listed")
	}
}

func TestAnUnknownTaskIsNotPending(t *testing.T) {
	g, _ := newGate(t, Config{Mode: Owner})
	if !errors.Is(g.Decide(id(7), true), ErrNotPending) {
		t.Fatal("approved a task that never waited")
	}
}

func TestTheTaskEndingEndsTheWaitAndNothingRuns(t *testing.T) {
	g, r := newGate(t, Config{Mode: Owner})
	ctx, cancel := context.WithCancel(context.Background())
	ch := start(g, ctx, task(1, "c", "o", "x"), &session{})
	waitPending(t, g, 1)
	cancel()
	o := get(t, ch)
	if !errors.Is(o.err, context.Canceled) || r.calls.Load() != 0 || len(g.List()) != 0 {
		t.Fatalf("%v calls %d", o.err, r.calls.Load())
	}
	if g.Decide(id(1), true) == nil {
		t.Fatal("approved a task that ended")
	}
}

func TestAFailedStatusSendDoesNotStopTheWait(t *testing.T) {
	g, r := newGate(t, Config{Mode: Owner})
	ch := start(g, context.Background(), task(1, "c", "o", "x"), &session{err: errors.New("send failed")})
	waitPending(t, g, 1)
	if err := g.Decide(id(1), true); err != nil {
		t.Fatal(err)
	}
	if o := get(t, ch); o.err != nil || r.calls.Load() != 1 {
		t.Fatalf("%v", o.err)
	}
}

func TestTheTimerLosingTheRaceToAnApprovalStillRunsTheTask(t *testing.T) {
	g, r := newGate(t, Config{Mode: Owner})
	e, why := g.enter(task(1, "c", "o", "x"))
	if why != "" {
		t.Fatal("refused")
	}
	if err := g.Decide(id(1), true); err != nil {
		t.Fatal(err)
	}
	// The timer branch of Handle calls settle after the approval was recorded.
	if d := g.settle(e, timedOut); d != approved {
		t.Fatalf("settle returned %v", d)
	}
	if r.calls.Load() != 0 {
		t.Fatal("unexpected run")
	}
	g.leave(e)
}

func TestLimitsOnWaitingTasks(t *testing.T) {
	g, r := newGate(t, Config{Mode: Owner, MaxPending: 3, MaxPerCaller: 2})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var chans []<-chan outcome
	chans = append(chans, start(g, ctx, task(1, "dev-a", "ann", "x"), &session{}))
	waitPending(t, g, 1)
	chans = append(chans, start(g, ctx, task(2, "dev-a", "ann", "x"), &session{}))
	waitPending(t, g, 2)

	// Third from the same caller: over the per-caller limit, rejected at once.
	o := get(t, start(g, ctx, task(3, "dev-a", "ann", "x"), &session{}))
	if failureText(t, o.err) != TextTooMany {
		t.Fatalf("per-caller: %v", o.err)
	}
	// Same owner on another device counts too.
	o = get(t, start(g, ctx, task(4, "dev-b", "ann", "x"), &session{}))
	if failureText(t, o.err) != TextTooMany {
		t.Fatalf("per-owner: %v", o.err)
	}
	// Another caller still fits, up to the total.
	chans = append(chans, start(g, ctx, task(5, "dev-c", "bob", "x"), &session{}))
	waitPending(t, g, 3)
	o = get(t, start(g, ctx, task(6, "dev-d", "cat", "x"), &session{}))
	if failureText(t, o.err) != TextTooMany {
		t.Fatalf("total: %v", o.err)
	}
	if r.calls.Load() != 0 {
		t.Fatal("a rejected task ran")
	}
	cancel()
	for _, c := range chans {
		get(t, c)
	}
	// Room again once they ended.
	if _, why := g.enter(task(7, "dev-a", "ann", "x")); why != "" {
		t.Fatal("no room after the others ended")
	}
}

func TestListShowsASafeBoundedPreviewOldestFirst(t *testing.T) {
	c := &clock{t: time.Unix(5000, 0)}
	g, _ := newGate(t, Config{Mode: Owner, Now: c.now, MaxPerCaller: 10})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	evil := "line1\nline2\ttab\x1b[2J\x1b]0;title\x07 rtl‮abc \x00\xff ok é" + strings.Repeat("y", 2*MaxPreview)
	start(g, ctx, task(2, "dev-2\x1b[31m", "bob\nx@example.com", evil), &session{})
	waitPending(t, g, 1)
	c.add(time.Second)
	start(g, ctx, task(1, "dev-1", "ann", "short"), &session{})
	waitPending(t, g, 2)

	l := g.List()
	if len(l) != 2 || l[0].TaskID != hex.EncodeToString(func() []byte { i := id(2); return i[:] }()) || l[1].Preview != "short" || l[1].Truncated {
		t.Fatalf("%+v", l)
	}
	p := l[0]
	if !p.Truncated || len(p.Preview) > MaxPreview {
		t.Fatalf("not bounded: truncated=%v len=%d", p.Truncated, len(p.Preview))
	}
	for _, r := range p.Preview + p.Caller + p.Owner {
		if r < 0x20 || r == 0x7f || r == 0x202e {
			t.Fatalf("control character %U survived in %q %q %q", r, p.Preview, p.Caller, p.Owner)
		}
	}
	if !strings.HasPrefix(p.Preview, "line1 line2 tab") || !strings.Contains(p.Preview, " ok é") {
		t.Fatalf("readable text lost: %q", p.Preview)
	}
	if p.Caller != "dev-2.[31m" || p.Owner != "bob x@example.com" {
		t.Fatalf("identity %q %q", p.Caller, p.Owner)
	}
	if !p.Received.Equal(time.Unix(5000, 0)) || !p.Expires.Equal(time.Unix(5000, 0).Add(DefaultTimeout)) {
		t.Fatalf("times %v %v", p.Received, p.Expires)
	}
}

func TestPrintable(t *testing.T) {
	cases := []struct {
		in    string
		limit int
		want  string
	}{
		{"plain text", 100, "plain text"},
		{"a\r\nb\tc", 100, "a  b c"},
		{"x\x1by", 100, "x.y"},
		{"‮⁦", 100, ".."},
		{"bad\xffbyte and more", 100, "bad.byte and more"},
		{"abcdef", 3, "abc"},
		{"ab\u00e9", 3, "ab"}, // cut inside a two-byte character: dropped
		{"ab\u00e9", 4, "ab\u00e9"},
		{"abc", 3, "abc"}, // exactly the limit: untouched
		{"ab\xff", 3, "ab."},
		{"\x80\x80\x80", 2, ""}, // continuation bytes only: nothing to keep, and no read before the start
		{"\u00e9\u00e9\u00e9", 4, "\u00e9\u00e9"},
		{"\ufffd real", 100, ". real"}, // a real U+FFFD is shown like an invalid byte
		{"", 10, ""},
	}
	for _, c := range cases {
		if got := printable(c.in, c.limit); got != c.want {
			t.Errorf("printable(%q, %d) = %q, want %q", c.in, c.limit, got, c.want)
		}
	}
}

func call(t *testing.T, m localsock.Method, params string) (any, string) {
	t.Helper()
	res, err := m(context.Background(), json.RawMessage(params))
	if err != nil {
		var re *localsock.RPCError
		if !errors.As(err, &re) {
			t.Fatalf("not an RPCError: %v", err)
		}
		return nil, re.Code
	}
	return res, ""
}

func TestMethods(t *testing.T) {
	g, r := newGate(t, Config{Mode: Owner})
	ms := g.Methods()
	if len(ms) != 3 {
		t.Fatalf("methods %v", ms)
	}
	// Nothing waits: an empty list, not null.
	res, code := call(t, ms["approvals"], "")
	if b, _ := json.Marshal(res); code != "" || string(b) != `{"pending":[],"untrusted":true}` {
		t.Fatalf("empty list %s %q", b, code)
	}

	ch := start(g, context.Background(), task(1, "c", "o", "hello"), &session{})
	waitPending(t, g, 1)
	res, _ = call(t, ms["approvals"], "")
	b, _ := json.Marshal(res)
	if !strings.Contains(string(b), `"preview":"hello"`) || !strings.Contains(string(b), `"task_id":"01000000000000000000000000000000"`) {
		t.Fatalf("list %s", b)
	}

	for _, bad := range []string{``, `null`, `{}`, `[]`, `{"task_id":5}`, `{"task_id":"zz"}`, `{"task_id":"0100"}`,
		`{"task_id":"0100000000000000000000000000000A"}`, `{"task_id":"010000000000000000000000000000000000"}`} {
		for _, m := range []string{"approve", "deny"} {
			if _, code := call(t, ms[m], bad); code != CodeBadParams {
				t.Fatalf("%s %q: code %q", m, bad, code)
			}
		}
	}
	if _, code := call(t, ms["approve"], `{"task_id":"02000000000000000000000000000000"}`); code != CodeNotFound {
		t.Fatalf("unknown task: %q", code)
	}
	res, code = call(t, ms["approve"], `{"task_id":"01000000000000000000000000000000"}`)
	b, _ = json.Marshal(res)
	if code != "" || string(b) != `{"task_id":"01000000000000000000000000000000","decision":"approved"}` {
		t.Fatalf("approve %s %q", b, code)
	}
	if _, code = call(t, ms["deny"], `{"task_id":"01000000000000000000000000000000"}`); code != CodeNotFound {
		t.Fatalf("deny after approve: %q", code)
	}
	if o := get(t, ch); o.err != nil || r.calls.Load() != 1 {
		t.Fatal("approved task did not run")
	}

	ch = start(g, context.Background(), task(3, "c", "o", "hello"), &session{})
	waitPending(t, g, 1)
	res, _ = call(t, ms["deny"], `{"task_id":"03000000000000000000000000000000"}`)
	b, _ = json.Marshal(res)
	if string(b) != `{"task_id":"03000000000000000000000000000000","decision":"denied"}` {
		t.Fatalf("deny %s", b)
	}
	if o := get(t, ch); failureText(t, o.err) != TextDenied {
		t.Fatal("denied task")
	}
}

func TestPreviewIsZeroedWhenTheTaskLeaves(t *testing.T) {
	g, _ := newGate(t, Config{Mode: Owner})
	e, _ := g.enter(task(1, "c", "o", "secret-plan"))
	keep := e.preview
	g.leave(e)
	for _, b := range keep {
		if b != 0 {
			t.Fatal("preview not zeroed")
		}
	}
	if len(g.waiting) != 0 {
		t.Fatal("still waiting")
	}
}

func TestTasksReceivedAtTheSameTimeAreListedByID(t *testing.T) {
	c := &clock{t: time.Unix(5000, 0)}
	g, _ := newGate(t, Config{Mode: Owner, Now: c.now, MaxPerCaller: 10})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start(g, ctx, task(2, "a", "a", "x"), &session{})
	waitPending(t, g, 1)
	start(g, ctx, task(1, "b", "b", "x"), &session{})
	waitPending(t, g, 2)
	l := g.List()
	if l[0].TaskID[:2] != "01" || l[1].TaskID[:2] != "02" {
		t.Fatalf("%+v", l)
	}
}

// FuzzPrintable: whatever a caller sends, what the owner's terminal is shown is bounded, valid UTF-8 and free of
// controls, escapes and format characters.
func FuzzPrintable(f *testing.F) {
	for _, s := range []string{"", "plain", "a\nb", "\x1b[2J", "\x1b]0;x\x07", "‮⁦", "\xff\xfe", "é\x80", "\u0085  ", strings.Repeat("é", 400)} {
		f.Add(s, 7)
	}
	f.Fuzz(func(t *testing.T, s string, limit int) {
		limit = min(max(limit, 0), 1024)
		got := printable(s, limit)
		if len(got) > limit*3 || !utf8.ValidString(got) { // '.' replaces at most one byte per character
			t.Fatalf("not bounded or not UTF-8: %q", got)
		}
		for _, r := range got {
			if r != ' ' && !unicode.IsPrint(r) || r == utf8.RuneError {
				t.Fatalf("%U survived in %q", r, got)
			}
		}
	})
}

func TestADuplicateTaskIDIsRefusedAndKeepsTheFirstEntry(t *testing.T) {
	g, r := newGate(t, Config{Mode: Owner})
	ctx, cancel := context.WithCancel(context.Background())
	first := start(g, ctx, task(1, "c", "o", "first"), &session{})
	waitPending(t, g, 1)
	o := get(t, start(g, context.Background(), task(1, "c", "o", "second"), &session{}))
	if failureText(t, o.err) != TextDuplicate {
		t.Fatalf("duplicate: %v", o.err)
	}
	l := g.List()
	if len(l) != 1 || l[0].Preview != "first" {
		t.Fatalf("the entry the owner saw was replaced or removed: %+v", l)
	}
	if err := g.Decide(id(1), true); err != nil {
		t.Fatal(err)
	}
	if o := get(t, first); o.err != nil || string(o.res) != "ran: first" || r.calls.Load() != 1 {
		t.Fatalf("%v %q", o.err, o.res)
	}
	cancel()
}

func TestAnExpiredTaskIsNotListed(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	g, _ := newGate(t, Config{Mode: Owner, Now: c.now, Timeout: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	ch := start(g, ctx, task(1, "c", "o", "x"), &session{})
	waitPending(t, g, 1)
	c.add(time.Hour - time.Second)
	if len(g.List()) != 1 {
		t.Fatal("not listed a second before the deadline")
	}
	c.add(time.Second)
	if len(g.List()) != 0 {
		t.Fatal("listed at the deadline, where Decide refuses")
	}
	cancel()
	get(t, ch)
}

// auditLog records the Audit calls.
type auditLog struct {
	mu sync.Mutex
	l  []string
}

func (a *auditLog) add(id [16]byte, state string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.l = append(a.l, hex.EncodeToString(id[:1])+" "+state)
}

func (a *auditLog) get() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return strings.Join(a.l, ", ")
}

// Every step of an approval is audited with the task id and a state, and nothing else.
func TestApprovalIsAudited(t *testing.T) {
	a := &auditLog{}
	g, _ := newGate(t, Config{Mode: Owner, Audit: a.add, Timeout: 100 * time.Millisecond, MaxPending: 1})
	// approved
	ch := start(g, context.Background(), task(1, "c", "o", "secret text"), &session{})
	waitPending(t, g, 1)
	if o := get(t, start(g, context.Background(), task(2, "d", "p", "x"), &session{})); failureText(t, o.err) != TextTooMany {
		t.Fatal("not refused")
	}
	_ = g.Decide(id(1), true)
	get(t, ch)
	// denied
	ch = start(g, context.Background(), task(3, "c", "o", "x"), &session{})
	waitPending(t, g, 1)
	_ = g.Decide(id(3), false)
	get(t, ch)
	// no answer
	get(t, start(g, context.Background(), task(4, "c", "o", "x"), &session{}))
	want := "02 APPROVAL_REFUSED, 01 APPROVAL_WAITING, 01 APPROVAL_APPROVED, 03 APPROVAL_WAITING, 03 APPROVAL_DENIED, 04 APPROVAL_WAITING, 04 APPROVAL_NO_ANSWER"
	if got := a.get(); got != want && got != strings.Replace(want, "02 APPROVAL_REFUSED, 01 APPROVAL_WAITING", "01 APPROVAL_WAITING, 02 APPROVAL_REFUSED", 1) {
		t.Fatalf("audit\n got %s\nwant %s", got, want)
	}
	if strings.Contains(a.get(), "secret") {
		t.Fatal("task text in the audit")
	}
	// A transparent gate asks nobody and audits nothing.
	a2 := &auditLog{}
	g2, _ := newGate(t, Config{Mode: None, Audit: a2.add})
	get(t, start(g2, context.Background(), task(5, "c", "o", "x"), &session{}))
	if a2.get() != "" {
		t.Fatalf("audit in mode none: %s", a2.get())
	}
}
