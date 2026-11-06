// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package skill_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/approval"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/skill"
	"github.com/kalahroudi/parley/internal/toolgate"
)

func TestDeclaringToolsMakesASkillToolUsing(t *testing.T) {
	withTools := skill.Skill{Tools: []toolgate.Tool{{Name: "grep"}}}
	if !withTools.Uses() || !(skill.Skill{ToolUsing: true}).Uses() || (skill.Skill{}).Uses() {
		t.Fatal("Uses")
	}
	if l := skill.Label(withTools); !strings.HasPrefix(l, "tool-using") {
		t.Fatalf("label %q", l)
	}
	if err := skill.Check(withTools, "linux"); !errors.Is(err, skill.ErrNeedsApproval) {
		t.Errorf("tools without owner approval: %v", err)
	}
	withTools.Approval = approval.Owner
	if err := skill.Check(withTools, "darwin"); err != nil {
		t.Errorf("tools with owner approval: %v", err)
	}
	if err := skill.Check(withTools, "windows"); !errors.Is(err, skill.ErrUnsupportedOS) {
		t.Errorf("tools on windows: %v", err)
	}
	for name, s := range map[string]skill.Skill{
		"bad tool name": {Tools: []toolgate.Tool{{Name: "a b"}}, Approval: approval.Owner},
		"duplicate":     {Tools: []toolgate.Tool{{Name: "a"}, {Name: "a"}}, Approval: approval.Owner},
	} {
		if err := skill.Check(s, "linux"); !errors.Is(err, skill.ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

type echoRunner struct{}

func (echoRunner) Run(_ context.Context, _ toolgate.Tool, args []string) (toolgate.Output, error) {
	return toolgate.Output{Data: []byte(strings.Join(args, " ")), Exit: 3}, nil
}

func newBroker(t *testing.T) *toolgate.Broker {
	t.Helper()
	m, err := toolgate.NewManifest([]toolgate.Tool{{Name: "grep"}, {Name: "fetch", Network: true}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := toolgate.New(toolgate.Config{Manifest: m, Runner: echoRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBridgeCarriesARequestAndItsReply(t *testing.T) {
	b := newBroker(t)
	br := skill.Bridge(b)
	task := bot.Task{ID: [16]byte{1}, Expiry: time.Now().Add(time.Hour)}
	type res struct {
		r   adapter.ToolReply
		err error
	}
	done := make(chan res, 1)
	waited := make(chan struct{})
	go func() {
		r, err := br.Call(context.Background(), task, "grep", []string{"a", "b"}, func() { close(waited) })
		done <- res{r, err}
	}()
	<-waited
	p := b.Pending()[0]
	if err := b.Decide(task.ID, p.Call, p.Digest, true, ""); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.r.Outcome != "exit" || r.r.Exit != 3 || !strings.Contains(string(r.r.Content), "\ngrep") && !strings.Contains(string(r.r.Content), "a b") {
		t.Fatalf("%+v", r.r)
	}
	br.End(task.ID)
	// Refused requests come back as an outcome, not an error.
	rr, err := br.Call(context.Background(), task, "rm", nil, nil)
	if err != nil || rr.Outcome != "refused" || rr.Content != nil {
		t.Fatalf("%+v %v", rr, err)
	}
}

func call(t *testing.T, m localsock.Method, params string) (map[string]any, string) {
	t.Helper()
	res, err := m(context.Background(), json.RawMessage(params))
	if err != nil {
		var re *localsock.RPCError
		if !errors.As(err, &re) {
			t.Fatalf("not an RPCError: %v", err)
		}
		return nil, re.Code
	}
	raw, _ := json.Marshal(res)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out, ""
}

func TestToolMethods(t *testing.T) {
	b := newBroker(t)
	ms := skill.ToolMethods(b)
	if len(ms) != 4 {
		t.Fatalf("%d methods", len(ms))
	}
	id := [16]byte{1}
	hexID := "01000000000000000000000000000000"
	ask := func(tool string, args ...string) <-chan toolgate.Reply {
		ch := make(chan toolgate.Reply, 1)
		go func() {
			r, _ := b.Call(context.Background(), id, time.Time{}, toolgate.Request{Tool: tool, Args: args}, nil)
			ch <- r
		}()
		for len(b.Pending()) == 0 {
			time.Sleep(time.Millisecond)
		}
		return ch
	}
	ch := ask("grep", "x y")
	list, code := call(t, ms["tool_calls"], `{}`)
	calls := list["calls"].([]any)
	if code != "" || list["untrusted"] != true || len(calls) != 1 || len(list["grants"].([]any)) != 0 {
		t.Fatalf("%v %s", list, code)
	}
	c := calls[0].(map[string]any)
	digest := c["digest"].(string)
	if c["tool"] != "grep" || c["task_id"] != hexID || c["call"] != float64(1) || c["args"].([]any)[0] != `"x y"` {
		t.Fatalf("%v", c)
	}
	base := `"task_id":"` + hexID + `","call":1`
	for name, tc := range map[string]struct{ method, params, code string }{
		"not json":       {"tool_approve", `[`, approval.CodeBadParams},
		"short id":       {"tool_approve", `{"task_id":"01","call":1}`, approval.CodeBadParams},
		"upper-case id":  {"tool_approve", `{"task_id":"0A000000000000000000000000000000","call":1}`, approval.CodeBadParams},
		"not hex":        {"tool_approve", `{"task_id":"zz000000000000000000000000000000","call":1}`, approval.CodeBadParams},
		"no call":        {"tool_approve", `{"task_id":"` + hexID + `"}`, approval.CodeBadParams},
		"call zero":      {"tool_approve", `{"task_id":"` + hexID + `","call":0}`, approval.CodeBadParams},
		"deny no call":   {"tool_deny", `{"task_id":"` + hexID + `","call":0}`, approval.CodeBadParams},
		"wrong digest":   {"tool_approve", `{` + base + `,"digest":"00"}`, skill.CodeDigest},
		"bad scope":      {"tool_approve", `{` + base + `,"digest":"` + digest + `","scope":"forever"}`, skill.CodeScope},
		"unknown call":   {"tool_approve", `{"task_id":"` + hexID + `","call":9,"digest":"` + digest + `"}`, approval.CodeNotFound},
		"revoke no tool": {"tool_revoke", `{"task_id":"` + hexID + `"}`, approval.CodeBadParams},
		"revoke bad":     {"tool_revoke", `{"task_id":"` + hexID + `","tool":"a b"}`, approval.CodeBadParams},
		"revoke bad id":  {"tool_revoke", `{"task_id":"x","tool":"grep"}`, approval.CodeBadParams},
		"revoke none":    {"tool_revoke", `{"task_id":"` + hexID + `","tool":"grep"}`, approval.CodeNotFound},
	} {
		if _, got := call(t, ms[tc.method], tc.params); got != tc.code {
			t.Errorf("%s: code %q, want %q", name, got, tc.code)
		}
	}
	if len(b.Pending()) != 1 {
		t.Fatal("a refused answer consumed the call")
	}
	res, code := call(t, ms["tool_approve"], `{`+base+`,"digest":"`+digest+`","scope":"task"}`)
	if code != "" || res["decision"] != "approved" || res["call"] != float64(1) || res["task_id"] != hexID {
		t.Fatalf("%v %s", res, code)
	}
	if r := <-ch; r.Outcome != toolgate.OutcomeExit {
		t.Fatalf("%+v", r)
	}
	list, _ = call(t, ms["tool_calls"], `{}`)
	if g := list["grants"].([]any); len(g) != 1 || g[0].(map[string]any)["tool"] != "grep" {
		t.Fatalf("%v", list)
	}
	res, code = call(t, ms["tool_revoke"], `{"task_id":"`+hexID+`","tool":"grep"}`)
	if code != "" || res["state"] != "revoked" || res["tool"] != "grep" {
		t.Fatalf("%v %s", res, code)
	}
	// A denial.
	ch = ask("fetch")
	res, code = call(t, ms["tool_deny"], `{`+strings.Replace(base, `"call":1`, `"call":2`, 1)+`}`)
	if code != "" || res["decision"] != "denied" {
		t.Fatalf("%v %s", res, code)
	}
	if r := <-ch; r.Outcome != toolgate.OutcomeDenied {
		t.Fatalf("%+v", r)
	}
}
