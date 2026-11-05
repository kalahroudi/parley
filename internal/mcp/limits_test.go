// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kalahroudi/parley/internal/localsock"
)

// Constant expressions have no statement for a mutant to be covered by.
func TestLimitsAndErrorCodesArePinned(t *testing.T) {
	if MaxMessage != 1<<20 || MaxConcurrent != 8 || MaxID != 256 || MaxArguments != 240<<10 {
		t.Error("a limit changed")
	}
	if codeParse != 32700 || codeRequest != 32600 || codeMethod != 32601 || codeParams != 32602 {
		t.Error("a JSON-RPC code changed")
	}
	rs := session(t, &fake{}, `x`, `{"jsonrpc":"2.0","id":1,"method":"nope"}`, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nope"}}`, `{"id":3}`)
	if len(rs) != 4 {
		t.Fatal(rs)
	}
	// Tool calls are answered from their own goroutines, so match replies by id.
	byID := map[any]any{}
	for _, r := range rs {
		byID[r["id"]] = r["error"].(map[string]any)["code"]
	}
	for id, want := range map[any]float64{nil: -32700, float64(1): -32601, float64(2): -32602, float64(3): -32600} {
		if byID[id] != want {
			t.Errorf("id %v: %v, want %v", id, byID[id], want)
		}
	}
}

func TestBlankLinesAndToolCallNotificationsAreSkipped(t *testing.T) {
	rs := session(t, &fake{},
		"", "   ",
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_tasks"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if len(rs) != 1 || rs[0]["id"] != float64(1) {
		t.Errorf("%v", rs)
	}
}

func TestIDBounds(t *testing.T) {
	for id, want := range map[string]bool{
		"": true, `"a"`: true, "0": true, "9": true, "-1": true, "12.5": true,
		"/": false, ":": false, "true": false, "null": false, "[]": false, "{}": false,
		`"` + strings.Repeat("a", MaxID-2) + `"`: true,
		`"` + strings.Repeat("a", MaxID-1) + `"`: false,
	} {
		if validID([]byte(id)) != want {
			t.Errorf("%.30q: want %v", id, want)
		}
	}
}

func TestArgumentSizeLimitIsExact(t *testing.T) {
	pad := func(n int) string { // arguments of exactly n bytes
		return `{"text":"` + strings.Repeat("a", n-len(`{"text":""}`)) + `"}`
	}
	for n, want := range map[int]bool{MaxArguments: true, MaxArguments + 1: false} {
		f := &fake{resp: okResp()}
		rs := session(t, f, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_task","arguments":`+pad(n)+`}}`)
		if got := len(f.calls) == 1; got != want || len(rs) != 1 {
			t.Errorf("%d bytes: forwarded=%v replies=%v", n, got, rs)
		}
	}
}

func TestSafeCodeBounds(t *testing.T) {
	for c, want := range map[string]string{
		"": "internal", "ok_code": "ok_code", strings.Repeat("a", 32): strings.Repeat("a", 32), strings.Repeat("a", 33): "internal",
		"Upper": "internal", "a b": "internal", "a-b": "internal", "x\n": "internal", "z": "z", "a": "a",
	} {
		if SafeCode(c) != want {
			t.Errorf("%q", c)
		}
	}
}

func TestOnlyToolsWithRequiredArgumentsSayWhichAreRequired(t *testing.T) {
	want := map[string]bool{"find_agents": false, "send_task": true, "get_task": true, "cancel_task": true, "list_tasks": false}
	for _, tl := range tools {
		if _, has := tl.InputSchema["required"]; has != want[tl.Name] {
			t.Errorf("%s: required present = %v", tl.Name, has)
		}
	}
}

func okResp() localsock.Response { return localsock.Response{OK: true, Result: json.RawMessage(`{}`)} }
