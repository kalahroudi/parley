// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"io"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func settle(t *testing.T, base int) {
	t.Helper()
	waitFor(t, func() bool { return runtime.NumGoroutine() <= base })
}

const tc = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`

// A line that says one thing twice, or in a spelling encoding/json would fold into the same field, is refused whole:
// whichever copy a reader keeps, it is not the one the sender can be held to. Nothing reaches the daemon.
func TestHostileDuplicateAndCaseVariantKeysAreRefused(t *testing.T) {
	f := &fake{}
	base := runtime.NumGoroutine()
	for name, line := range map[string]string{
		"duplicate method":    `{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":{"name":"get_task"}}`,
		"duplicate id":        `{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}`,
		"duplicate jsonrpc":   `{"jsonrpc":"2.0","jsonrpc":"1.0","id":1,"method":"ping"}`,
		"case variant":        `{"jsonrpc":"2.0","id":1,"METHOD":"tools/call","params":{"name":"get_task"}}`,
		"escaped duplicate":   `{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}`,
		"unknown field":       `{"jsonrpc":"2.0","id":1,"method":"ping","admin":true}`,
		"duplicate name":      tc + `{"name":"get_task","name":"send_task"}}`,
		"name case variant":   tc + `{"Name":"get_task"}}`,
		"unknown call field":  tc + `{"name":"get_task","admin":true}}`,
		"duplicate arguments": tc + `{"name":"get_task","arguments":{},"arguments":{}}}`,
		"duplicate argument":  tc + `{"name":"send_task","arguments":{"to":"a","to":"b"}}}`,
		"argument case pair":  tc + `{"name":"send_task","arguments":{"to":"a","To":"b"}}}`,
		"array arguments":     tc + `{"name":"get_task","arguments":[]}}`,
	} {
		rs := session(t, f, line)
		if len(rs) != 1 || rs[0]["error"] == nil || rs[0]["result"] != nil {
			t.Errorf("%s: %v", name, rs)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("a refused line reached the daemon: %v", f.calls)
	}
	settle(t, base)
	// the same calls without the duplicate go through
	if rs := session(t, f, tc+`{"name":"send_task","arguments":{"to":"a","text":"b"},"_meta":{"progressToken":1}}}`); len(rs) != 1 || rs[0]["result"] == nil || len(f.calls) != 1 {
		t.Fatalf("%v %v", rs, f.calls)
	}
}

// Nesting far past what the decoder allows, inside the size limit, is refused without the daemon seeing it, and
// quickly: no recursion of ours is involved.
func TestHostileDeepNestingIsRefused(t *testing.T) {
	f := &fake{}
	deep := strings.Repeat(`[`, MaxArguments-100)
	for name, line := range map[string]string{
		"in the arguments": tc + `{"name":"get_task","arguments":{"a":` + deep + `}}}`,
		"in the params":    `{"jsonrpc":"2.0","id":1,"method":"ping","params":` + deep,
		"in an id":         `{"jsonrpc":"2.0","id":` + deep + `,"method":"ping"}`,
	} {
		if rs := session(t, f, line); len(rs) != 1 || rs[0]["error"] == nil {
			t.Errorf("%s: %v", name, rs)
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("reached the daemon")
	}
}

// Control, NUL, bidi and invalid UTF-8 in names and ids are never echoed, and every reply is one valid UTF-8 line.
func TestHostileCharactersNeverComeBackInAReply(t *testing.T) {
	f := &fake{}
	const canary = "SECRET-CANARY"
	var out safeBuf
	s := &Server{Call: f.Call}
	lines := []string{
		tc + "{\"name\":\"" + canary + "\x00\"}}",
		tc + "{\"name\":\"" + canary + "‮\"}}",
		tc + "{\"name\":\"" + canary + "\xff\"}}",
		tc + "{\"name\":\"" + canary + "\\u0000\\u202e\"}}",
		"{\"jsonrpc\":\"2.0\",\"id\":\"" + canary + "\xff‮\",\"method\":\"" + canary + "\x01\"}",
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + canary + "‮\"}",
		canary + "\xff\x00",
		"\x00\x00\x00",
	}
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !utf8.ValidString(got) || strings.Count(got, "\n") != len(strings.Split(strings.TrimSuffix(got, "\n"), "\n")) {
		t.Fatalf("not lines of UTF-8: %q", got)
	}
	// an id is echoed (a client chooses it and needs it back), but a method, a tool name and other text are not
	for _, l := range strings.Split(strings.TrimSpace(got), "\n") {
		if strings.Contains(l, canary) && !strings.Contains(l, `"id":"`+canary) {
			t.Errorf("echoed: %q", l)
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("reached the daemon")
	}
}

// Two calls under one id could not be told apart, answered or canceled: the second is refused while the first runs,
// and the first still gets its one answer and can still be canceled.
func TestHostileDuplicateIDInFlightIsRefused(t *testing.T) {
	f := &fake{block: make(chan struct{})}
	base := runtime.NumGoroutine()
	pr, pw := io.Pipe()
	var out safeBuf
	done := make(chan error, 1)
	go func() { done <- (&Server{Call: f.Call}).Serve(context.Background(), pr, &out) }()
	call := tc + `{"name":"get_task","arguments":{}}}` + "\n"
	io.WriteString(pw, call)
	waitFor(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) == 1 })
	io.WriteString(pw, call)
	waitFor(t, func() bool { return strings.Contains(out.String(), "request id in use") })
	close(f.block)
	waitFor(t, func() bool { return strings.Contains(out.String(), `"result"`) })
	// the id is free again once the first call has been answered
	io.WriteString(pw, call)
	waitFor(t, func() bool { return strings.Count(out.String(), `"result"`) == 2 })
	pw.Close()
	<-done
	if len(f.calls) != 2 {
		t.Fatalf("%d calls reached the daemon, want 2", len(f.calls))
	}
	settle(t, base)
}

// A flood of tiny messages is answered line by line, and tool calls past the concurrency limit wait instead of
// starting more goroutines; once the input ends and the calls finish nothing is left.
func TestHostileFloodOfTinyMessagesIsBounded(t *testing.T) {
	base := runtime.NumGoroutine()
	var lines []string
	for i := 0; i < 5000; i++ {
		lines = append(lines, `{"jsonrpc":"2.0","id":`+strconv.Itoa(i)+`,"method":"ping"}`, `{"jsonrpc":"2.0","method":"notifications/nothing"}`, "", `x`)
	}
	rs := session(t, &fake{}, lines...)
	pings, errs := 0, 0
	for _, r := range rs {
		if r["error"] != nil {
			errs++
		} else {
			pings++
		}
	}
	if pings != 5000 || errs != 5000 {
		t.Fatalf("%d answers and %d errors", pings, errs)
	}
	// calls: more than MaxConcurrent blocked at once never run more than MaxConcurrent at a time
	f := &fake{block: make(chan struct{})}
	pr, pw := io.Pipe()
	var out safeBuf
	done := make(chan error, 1)
	go func() { done <- (&Server{Call: f.Call}).Serve(context.Background(), pr, &out) }()
	go func() {
		for i := 0; i < 5*MaxConcurrent; i++ {
			io.WriteString(pw, `{"jsonrpc":"2.0","id":`+strconv.Itoa(i)+`,"method":"tools/call","params":{"name":"get_task","arguments":{}}}`+"\n")
		}
	}()
	waitFor(t, func() bool { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) == MaxConcurrent })
	if n := runtime.NumGoroutine(); n > base+MaxConcurrent*2+10 {
		t.Fatalf("%d goroutines for %d running calls", n-base, MaxConcurrent)
	}
	close(f.block)
	waitFor(t, func() bool { return strings.Count(out.String(), `"result"`) == 5*MaxConcurrent })
	pw.Close()
	<-done
	settle(t, base)
}

// A client that connects and says nothing costs one reader goroutine, and ending the session (the context) frees it
// even though the client never speaks again.
func TestHostileSilentClientIsLetGoWhenTheSessionEnds(t *testing.T) {
	base := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- (&Server{Call: (&fake{}).Call}).Serve(ctx, pr, io.Discard) }()
	io.WriteString(pw, `{"jsonrpc":"2.0","id":1,"method":"pi`) // half a line, then silence
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	pw.Close() // the reader goroutine ends with its input, as documented
	settle(t, base)
}
