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
	"testing"

	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/logx"
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

func runCLI(t *testing.T, home, stdin string, args ...string) (code int, out, errw string) {
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
		{[]string{"list", "-state", "TASK_STATE_COMPLETED", "-limit", "10", "-cursor", "00"}, "", "list_tasks", `{"state":"TASK_STATE_COMPLETED","limit":10,"cursor":"00"}`},
	} {
		var s seen
		home := daemonWith(t, map[string]localsock.Method{tc.method: record(&s, map[string]any{"ok": true}, nil)})
		code, out, errw := runCLI(t, home, tc.stdin, tc.args...)
		if code != 0 || errw != "" || !strings.Contains(out, `"ok": true`) {
			t.Errorf("%v: %d %q %q", tc.args, code, out, errw)
		}
		want := tc.params
		if want == `null` {
			want = `{}`
		}
		if s.params != want && !(tc.method == "list_tasks" && s.params == "") {
			t.Errorf("%v sent %s, want %s", tc.args, s.params, want)
		}
	}
}

func TestUntrustedResultsCarryANoticeOnStderrOnly(t *testing.T) {
	home := daemonWith(t, map[string]localsock.Method{"get_task": record(&seen{}, map[string]any{"content": "x", "untrusted": true}, nil)})
	code, out, errw := runCLI(t, home, "", "get", "abc")
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
	if code, out, errw := runCLI(t, home, "", "get", "abc"); code != 1 || out != "" || errw != "error: not_found\n" {
		t.Errorf("%d %q %q", code, out, errw)
	}
	if code, _, errw := runCLI(t, home, "", "cancel", "abc"); code != 1 || errw != "error: internal\n" {
		t.Errorf("%d %q", code, errw)
	}
	if code, _, errw := runCLI(t, home, "", "list"); code != 1 || errw != "error: unknown_method\n" {
		t.Errorf("%d %q", code, errw)
	}
}

func TestNoDaemon(t *testing.T) {
	code, _, errw := runCLI(t, t.TempDir(), "", "list")
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
		{"send", "-to", "dev-2", "-expiry", "500ms", "x"}, {"send", "-to", "dev-2", "-expiry", "-5s", "x"},
		{"get", "-wait", "1500ms", "abc"}, {"get", "-wait", "-1s", "abc"},
	} {
		if code, out, _ := runCLI(t, home, "", args...); code != 2 || out != "" {
			t.Errorf("%v: %d %q", args, code, out)
		}
	}
}

func TestSendReadsAtMostTheTaskLimitFromStdin(t *testing.T) {
	var s seen
	home := daemonWith(t, map[string]localsock.Method{"send_task": record(&s, map[string]any{}, nil)})
	// The daemon refuses what is too large; the CLI must not read without bound.
	big := strings.Repeat("a", 1<<20)
	runCLI(t, home, big, "send", "-to", "dev-2", "-")
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
	code, out, errw := runCLI(t, home, in, "mcp")
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
