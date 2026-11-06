// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/skill"
	"github.com/kalahroudi/parley/internal/toolgate"
	"github.com/kalahroudi/parley/internal/ttyconfirm"
)

type countRunner struct{ n atomic.Int32 }

func (r *countRunner) Run(_ context.Context, _ toolgate.Tool, args []string) (toolgate.Output, error) {
	r.n.Add(1)
	return toolgate.Output{Data: []byte(strings.Join(args, " "))}, nil
}

// An owner approves, denies and revokes tool calls through the real socket: what is shown is what runs, a "yes" on
// standard input counts for nothing, and nothing runs before the answer.
func TestJG07OwnerApprovesToolCallsThroughTheCLI(t *testing.T) {
	m, err := toolgate.NewManifest([]toolgate.Tool{{Name: "grep"}, {Name: "fetch", Network: true}})
	if err != nil {
		t.Fatal(err)
	}
	r := &countRunner{}
	b, err := toolgate.New(toolgate.Config{Manifest: m, Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	home := daemonWith(t, skill.ToolMethods(b))
	id := [16]byte{1}
	hexID := "01000000000000000000000000000000"
	ask := func(tool string, args ...string) <-chan toolgate.Reply {
		ch := make(chan toolgate.Reply, 1)
		go func() {
			rep, _ := b.Call(context.Background(), id, time.Time{}, toolgate.Request{Tool: tool, Args: args}, nil)
			ch <- rep
		}()
		for i := 0; i < 2000 && len(b.Pending()) == 0; i++ {
			time.Sleep(time.Millisecond)
		}
		if len(b.Pending()) == 0 {
			t.Fatal("the call never waited")
		}
		return ch
	}
	old := askOwner
	defer func() { askOwner = old }()
	var prompts []string
	askOwner = func(p string) (bool, error) { prompts = append(prompts, p); return true, nil }

	ch := ask("grep", "-n", "a b é")
	code, out, _ := run(t, home, "", "approve")
	if code == 0 || out != "" { // no "approvals" method on this socket: the task listing fails first
		t.Fatalf("list without the task methods: %d %q", code, out)
	}
	code, out, errw := run(t, home, "", "approve", hexID+".1")
	if code != 0 || !strings.Contains(out, `"decision": "approved"`) || errw != "" {
		t.Fatalf("approve: %d %q %q", code, out, errw)
	}
	if rep := <-ch; rep.Outcome != toolgate.OutcomeOK || r.n.Load() != 1 {
		t.Fatalf("%+v ran %d", rep, r.n.Load())
	}
	p := prompts[0]
	if !strings.Contains(p, "tool: grep") || !strings.Contains(p, `[0] "-n"`) || !strings.Contains(p, `[1] "a b \u00e9"`) ||
		!strings.Contains(p, "digest: "+toolgate.Digest(id, 1, "grep", false, []string{"-n", "a b é"})) ||
		strings.Contains(p, "\x1b") || !strings.Contains(p, "this request only") || strings.Contains(p, "NETWORK") {
		t.Fatalf("what the owner was shown:\n%q", p)
	}

	// No terminal, or a no: nothing runs and the call keeps waiting.
	ch = ask("fetch", "https://example.test")
	askOwner = func(string) (bool, error) { return false, ttyconfirm.ErrNoTerminal }
	if code, _, errw = run(t, home, "yes\n", "approve", hexID+".2"); code != 1 || !strings.Contains(errw, "no terminal") || r.n.Load() != 1 || len(b.Pending()) != 1 {
		t.Fatalf("without a terminal: %d %q", code, errw)
	}
	askOwner = func(string) (bool, error) { return false, nil }
	if code, _, errw = run(t, home, "", "approve", hexID+".2"); code != 1 || !strings.Contains(errw, "not approved") || len(b.Pending()) != 1 {
		t.Fatalf("answered no: %d %q", code, errw)
	}
	// A network tool is shown as such and cannot be granted for the task.
	askOwner = func(p string) (bool, error) { prompts = append(prompts, p); return true, nil }
	if code, _, errw = run(t, home, "", "approve", "-scope", "task", hexID+".2"); code != 1 || errw != "error: bad_scope\n" || !strings.Contains(prompts[len(prompts)-1], "NEEDS THE NETWORK") {
		t.Fatalf("network grant: %d %q", code, errw)
	}
	if code, out, _ = run(t, home, "", "approve", "-deny", hexID+".2"); code != 0 || !strings.Contains(out, `"decision": "denied"`) {
		t.Fatalf("deny: %d %q", code, out)
	}
	if rep := <-ch; rep.Outcome != toolgate.OutcomeDenied || r.n.Load() != 1 {
		t.Fatalf("%+v ran %d", rep, r.n.Load())
	}

	// A task-scope approval makes a grant, which the owner lists and revokes.
	ch = ask("grep", "x")
	if code, _, _ = run(t, home, "", "approve", "-scope", "task", hexID+".3"); code != 0 {
		t.Fatalf("grant: %d", code)
	}
	<-ch
	if g := b.Grants(); len(g) != 1 {
		t.Fatalf("%+v", g)
	}
	if code, out, _ = run(t, home, "", "approve", "-revoke", hexID+".grep"); code != 0 || !strings.Contains(out, `"state": "revoked"`) || len(b.Grants()) != 0 {
		t.Fatalf("revoke: %d %q", code, out)
	}

	// Mistakes are refused with a fixed code or a usage message.
	for _, args := range [][]string{{"approve", hexID + ".x"}, {"approve", hexID + ".0"}, {"approve", hexID + ".9"}, {"approve", "-deny", hexID + ".x"}} {
		if code, _, errw = run(t, home, "", args...); code != 1 || errw != "error: not_found\n" && errw != "error: bad_params\n" {
			t.Errorf("%v: %d %q", args, code, errw)
		}
	}
	for _, args := range [][]string{{"approve", "-revoke"}, {"approve", "-revoke", hexID}, {"approve", "-deny", "-revoke", hexID + ".grep"}} {
		if code, _, _ = run(t, home, "", args...); code != 2 {
			t.Errorf("%v: %d", args, code)
		}
	}
}

func TestListingShowsToolCallsAndGrantsToo(t *testing.T) {
	m, _ := toolgate.NewManifest([]toolgate.Tool{{Name: "grep"}})
	b, _ := toolgate.New(toolgate.Config{Manifest: m, Runner: &countRunner{}})
	methods := skill.ToolMethods(b)
	methods["approvals"] = func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"pending": []any{}, "untrusted": true}, nil
	}
	home := daemonWith(t, methods)
	go func() {
		_, _ = b.Call(context.Background(), [16]byte{2}, time.Time{}, toolgate.Request{Tool: "grep", Args: []string{"x"}}, nil)
	}()
	for i := 0; i < 2000 && len(b.Pending()) == 0; i++ {
		time.Sleep(time.Millisecond)
	}
	code, out, errw := run(t, home, "", "approve")
	if code != 0 || !strings.Contains(out, `"pending"`) || !strings.Contains(out, `"calls"`) || !strings.Contains(out, `"digest"`) || !strings.Contains(errw, "UNTRUSTED") {
		t.Fatalf("%d %q %q", code, out, errw)
	}
}

func TestPlainReplacesWhatATerminalCouldAct(t *testing.T) {
	if got := plain("a\x1b[2Jé\n~ z"); got != "a.[2J..~ z" {
		t.Fatalf("%q", got)
	}
}
