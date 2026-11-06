// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/approval"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/ttyconfirm"
)

type seen struct {
	mu     sync.Mutex
	method string
	params string
}

// daemonWith serves the given methods on the socket a parley-cli finds through $PARLEY_HOME.
func daemonWith(t *testing.T, methods map[string]localsock.Method) (home string) {
	t.Helper()
	base := ""
	if runtime.GOOS != "windows" {
		base = "/tmp" // unix socket paths are short
	}
	home, err := os.MkdirTemp(base, "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	ln, err := localsock.Listen(home + "/parleyd.sock")
	if err != nil {
		t.Fatal(err)
	}
	srv := &localsock.Server{Log: logx.New(&bytes.Buffer{}), UID: os.Geteuid(), Methods: methods}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return home
}

func record(s *seen, result any, err error) localsock.Method {
	return func(_ context.Context, p json.RawMessage) (any, error) {
		s.mu.Lock()
		s.params = string(p)
		s.mu.Unlock()
		return result, err
	}
}

func run(t *testing.T, home, stdin string, args ...string) (code int, out, errw string) {
	t.Helper()
	var o, e bytes.Buffer
	getenv := func(k string) string {
		if k == "PARLEY_HOME" {
			return home
		}
		return ""
	}
	code = execute(context.Background(), args, strings.NewReader(stdin), &o, &e, func() (string, error) { return "", errors.New("unused") }, getenv, tools{})
	return code, o.String(), e.String()
}

func TestCommandsSendTheRightRequests(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		stdin  string
		method string
		params string
	}{
		{[]string{"find", "code", "review"}, "", "find_agents", `{"text":"code review"}`},
		{[]string{"find", "-tag", "go", "-limit", "5", "-cursor", "ab"}, "", "find_agents", `{"tag":"go","limit":5,"cursor":"ab"}`},
		{[]string{"send", "-to", "dev-2:ab", "do", "this"}, "", "send_task", `{"agent":"dev-2:ab","text":"do this"}`},
		{[]string{"send", "-to", "dev-2", "-expiry", "2m", "-"}, "from stdin\n", "send_task", `{"agent":"dev-2","text":"from stdin","expiry_seconds":120}`},
		{[]string{"send", "-task", "aa", "this", "one"}, "", "send_task", `{"task_id":"aa","text":"this one"}`},
		{[]string{"get", "abc"}, "", "get_task", `{"task_id":"abc"}`},
		{[]string{"get", "-wait", "15s", "abc"}, "", "get_task", `{"task_id":"abc","wait_seconds":15}`},
		{[]string{"get", "abc", "-wait", "3s"}, "", "get_task", `{"task_id":"abc","wait_seconds":3}`},
		{[]string{"cancel", "abc"}, "", "cancel_task", `{"task_id":"abc"}`},
		{[]string{"list"}, "", "list_tasks", `null`},
		{[]string{"approve"}, "", "approvals", `null`},
		{[]string{"approve", "-deny", "ab"}, "", "deny", `{"task_id":"ab"}`},
		{[]string{"approve", "ab", "-deny"}, "", "deny", `{"task_id":"ab"}`},
		{[]string{"list", "-state", "TASK_STATE_COMPLETED", "-limit", "10", "-cursor", "00"}, "", "list_tasks", `{"state":"TASK_STATE_COMPLETED","limit":10,"cursor":"00"}`},
	} {
		var s seen
		home := daemonWith(t, map[string]localsock.Method{tc.method: record(&s, map[string]any{"ok": true}, nil)})
		code, out, errw := run(t, home, tc.stdin, tc.args...)
		if code != 0 || errw != "" || !strings.Contains(out, `"ok": true`) {
			t.Errorf("%v: %d %q %q", tc.args, code, out, errw)
		}
		want := tc.params
		if want == `null` {
			want = `{}`
		}
		if s.params != want && !((tc.method == "list_tasks" || tc.method == "approvals") && s.params == "") {
			t.Errorf("%v sent %s, want %s", tc.args, s.params, want)
		}
	}
}

func TestUntrustedResultsCarryANoticeOnStderrOnly(t *testing.T) {
	home := daemonWith(t, map[string]localsock.Method{"get_task": record(&seen{}, map[string]any{"content": "x", "untrusted": true}, nil)})
	code, out, errw := run(t, home, "", "get", "abc")
	if code != 0 || !strings.Contains(errw, "UNTRUSTED") || strings.Contains(out, "UNTRUSTED") {
		t.Fatalf("%d out=%q err=%q", code, out, errw)
	}
	var v map[string]any
	if json.Unmarshal([]byte(out), &v) != nil {
		t.Errorf("stdout is not JSON: %q", out)
	}
}

func TestDaemonErrorsAreShownAsFixedCodes(t *testing.T) {
	home := daemonWith(t, map[string]localsock.Method{
		"get_task":    record(&seen{}, nil, &localsock.RPCError{Code: "not_found"}),
		"cancel_task": record(&seen{}, nil, errors.New("SECRET internal detail")),
	})
	if code, out, errw := run(t, home, "", "get", "abc"); code != 1 || out != "" || errw != "error: not_found\n" {
		t.Errorf("%d %q %q", code, out, errw)
	}
	if code, _, errw := run(t, home, "", "cancel", "abc"); code != 1 || errw != "error: internal\n" {
		t.Errorf("%d %q", code, errw)
	}
	if code, _, errw := run(t, home, "", "list"); code != 1 || errw != "error: unknown_method\n" {
		t.Errorf("%d %q", code, errw)
	}
}

func TestNoDaemon(t *testing.T) {
	code, _, errw := run(t, t.TempDir(), "", "list")
	if code != 1 || !strings.Contains(errw, "not running") {
		t.Fatalf("%d %q", code, errw)
	}
}

func TestBadUsage(t *testing.T) {
	home := t.TempDir()
	for _, args := range [][]string{
		{"send", "-to", "dev-2"},               // no text
		{"get"}, {"get", "a", "b"}, {"cancel"}, // task id missing or doubled
		{"list", "extra"}, {"find", "-bogus"}, {"send", "-bogus"}, {"get", "-bogus", "x"}, {"list", "-bogus"},
		{"mcp", "extra"},
		{"approve", "a", "b"}, {"approve", "-deny"}, {"approve", "-bogus"},
		{"send", "-to", "dev-2", "-expiry", "500ms", "x"}, {"send", "-to", "dev-2", "-expiry", "-5s", "x"},
		{"get", "-wait", "1500ms", "abc"}, {"get", "-wait", "-1s", "abc"},
	} {
		if code, out, _ := run(t, home, "", args...); code != 2 || out != "" {
			t.Errorf("%v: %d %q", args, code, out)
		}
	}
}

func TestSendReadsAtMostTheTaskLimitFromStdin(t *testing.T) {
	var s seen
	home := daemonWith(t, map[string]localsock.Method{"send_task": record(&s, map[string]any{}, nil)})
	// The daemon refuses what is too large; the CLI must not read without bound.
	big := strings.Repeat("a", 1<<20)
	run(t, home, big, "send", "-to", "dev-2", "-")
	if len(s.params) > 40000 {
		t.Fatalf("sent %d bytes", len(s.params))
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("closed") }

func TestUnreadableStdin(t *testing.T) {
	var o, e bytes.Buffer
	s := &session{in: failReader{}, out: &o, errw: &e}
	if code := s.run(context.Background(), []string{"send", "-to", "dev-2", "-"}); code != 2 || !strings.Contains(e.String(), "standard input") {
		t.Fatalf("%d %q", code, e.String())
	}
}

func TestMCPOverTheRealSocket(t *testing.T) {
	home := daemonWith(t, map[string]localsock.Method{"find_agents": record(&seen{}, map[string]any{"agents": []string{}, "untrusted": true}, nil)})
	in := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_agents","arguments":{"text":"x"}}}` + "\n"
	code, out, errw := run(t, home, in, "mcp")
	if code != 0 || errw != "" || strings.Count(out, "\n") != 2 || !strings.Contains(out, "UNTRUSTED CONTENT") {
		t.Fatalf("%d %q %q", code, out, errw)
	}
}

func TestMCPSessionEndsWithAnErrorOnHostileInput(t *testing.T) {
	var o, e bytes.Buffer
	s := &session{in: strings.NewReader(strings.Repeat("a", 2<<20)), out: &o, errw: &e}
	if code := s.run(context.Background(), []string{"mcp"}); code != 1 || !strings.Contains(e.String(), "mcp session ended") {
		t.Fatalf("%d %q", code, e.String())
	}
}

func TestNoConfigDirectory(t *testing.T) {
	var o, e bytes.Buffer
	code := execute(context.Background(), []string{"list"}, nil, &o, &e, func() (string, error) { return "", errors.New("no home") }, func(string) string { return "" }, tools{})
	if code != 1 || e.String() != "error: daemon: no user config directory: no home\n" {
		t.Fatalf("%d %q", code, e.String())
	}
}

// holdBot counts how often the bot behind the gate ran.
type holdBot struct{ ran atomic.Int32 }

func (b *holdBot) Handle(context.Context, bot.Task, bot.Session) ([]byte, error) {
	b.ran.Add(1)
	return []byte("done"), nil
}

type quietSession struct{}

func (quietSession) Status(context.Context, []byte) error        { return nil }
func (quietSession) Ask(context.Context, []byte) ([]byte, error) { return nil, errors.New("unused") }

// TestJG01OwnerApprovesAndDeniesThroughTheCLI is journey G over the real socket: a task held for the owner runs
// only after `parley-cli approve <id>`, is rejected after `approve -deny <id>`, and the MCP server cannot approve.
func TestJG01OwnerApprovesAndDeniesThroughTheCLI(t *testing.T) {
	b := &holdBot{}
	g, err := approval.New(approval.Config{Bot: b, Mode: approval.Owner})
	if err != nil {
		t.Fatal(err)
	}
	home := daemonWith(t, g.Methods())
	hold := func(n byte, text string) <-chan error {
		ch := make(chan error, 1)
		go func() {
			_, err := g.Handle(context.Background(), bot.Task{ID: [16]byte{n}, Caller: "dev-2", Owner: "ann@example.com", Content: []byte(text)}, quietSession{})
			ch <- err
		}()
		return ch
	}
	waitFor := func(n int) {
		for i := 0; i < 2000 && len(g.List()) != n; i++ {
			time.Sleep(time.Millisecond)
		}
		if len(g.List()) != n {
			t.Fatalf("%d tasks never waited", n)
		}
	}

	var prompts []string
	answer := func(p string) (bool, error) { prompts = append(prompts, p); return true, nil }
	old := askOwner
	askOwner = answer
	defer func() { askOwner = old }()
	ch := hold(1, "run the tests\x1b[2J")
	waitFor(1)
	code, out, errw := run(t, home, "", "approve")
	if code != 0 || !strings.Contains(out, "run the tests.[2J") || strings.Contains(out, "\x1b") || !strings.Contains(errw, "UNTRUSTED") {
		t.Fatalf("list: %d %q %q", code, out, errw)
	}
	id := "01000000000000000000000000000000"
	if b.ran.Load() != 0 {
		t.Fatal("ran before approval")
	}
	// Without a terminal, or with a no, nothing is approved; a "yes" on standard input counts for nothing.
	askOwner = func(string) (bool, error) { return false, ttyconfirm.ErrNoTerminal }
	if code, _, errw = run(t, home, "yes\n", "approve", id); code != 1 || !strings.Contains(errw, "no terminal") || b.ran.Load() != 0 || len(g.List()) != 1 {
		t.Fatalf("approve without a terminal: %d %q ran %d", code, errw, b.ran.Load())
	}
	askOwner = func(string) (bool, error) { return false, nil }
	if code, _, errw = run(t, home, "yes\n", "approve", id); code != 1 || !strings.Contains(errw, "not approved") || b.ran.Load() != 0 || len(g.List()) != 1 {
		t.Fatalf("approve answered no: %d %q", code, errw)
	}
	askOwner = answer
	if code, _, errw = run(t, home, "", "approve", "05000000000000000000000000000000"); code != 1 || errw != "error: not_found\n" || len(prompts) != 0 {
		t.Fatalf("approve of a task that does not wait: %d %q prompts %q", code, errw, prompts)
	}
	if code, out, errw = run(t, home, "", "approve", id); code != 0 || !strings.Contains(out, `"decision": "approved"`) || errw != "" {
		t.Fatalf("approve: %d %q %q", code, out, errw)
	}
	if err := <-ch; err != nil || b.ran.Load() != 1 {
		t.Fatalf("after approve: %v ran %d", err, b.ran.Load())
	}
	if len(prompts) != 1 || !strings.Contains(prompts[0], "run the tests.[2J") || !strings.Contains(prompts[0], "dev-2") || strings.Contains(prompts[0], "\x1b") {
		t.Fatalf("the owner was not shown the task: %q", prompts)
	}
	if code, _, errw = run(t, home, "", "approve", id); code != 1 || errw != "error: not_found\n" {
		t.Fatalf("second approve: %d %q", code, errw)
	}

	ch = hold(2, "delete everything")
	waitFor(1)
	if code, out, _ = run(t, home, "", "approve", "-deny", "02000000000000000000000000000000"); code != 0 || !strings.Contains(out, `"decision": "denied"`) {
		t.Fatalf("deny: %d %q", code, out)
	}
	var f *bot.Failure
	if err := <-ch; !errors.As(err, &f) || f.Message != approval.TextDenied || b.ran.Load() != 1 {
		t.Fatalf("after deny: %v ran %d", err, b.ran.Load())
	}
	if code, _, errw = run(t, home, "", "approve", "nonsense"); code != 1 || errw != "error: not_found\n" {
		t.Fatalf("bad id: %d %q", code, errw)
	}

	// A model that talks MCP cannot approve its own work: there is no such tool.
	in := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"approve","arguments":{"task_id":"` + id + `"}}}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}` + "\n"
	_, out, _ = run(t, home, in, "mcp")
	if strings.Contains(out, `"name":"approve"`) || strings.Contains(out, `"name":"deny"`) || strings.Contains(out, `"name":"approvals"`) {
		t.Fatalf("approval is reachable through MCP: %s", out)
	}
}

func TestJG01NoAnswerRejectsTheTask(t *testing.T) {
	b := &holdBot{}
	g, _ := approval.New(approval.Config{Bot: b, Mode: approval.Owner, Timeout: 30 * time.Millisecond})
	_, err := g.Handle(context.Background(), bot.Task{ID: [16]byte{3}}, quietSession{})
	var f *bot.Failure
	if !errors.As(err, &f) || f.Message != approval.TextTimedOut || b.ran.Load() != 0 {
		t.Fatalf("%v ran %d", err, b.ran.Load())
	}
}
