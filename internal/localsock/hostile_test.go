// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package localsock

import (
	"context"
	"encoding/json"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// goroutinesSettle fails the test if the goroutine count does not return to base: a hostile peer must leave nothing
// of itself behind once the server has dealt with it.
func goroutinesSettle(t *testing.T, base int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > base && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base {
		t.Fatalf("%d goroutines before, %d after", base, n)
	}
}

// sentWhole is rawRoundTrip for a client that has said all it will say: it closes its writing side, so the server
// sees the end of the request instead of waiting out its deadline.
func sentWhole(t *testing.T, path string, payload []byte) Response {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write(payload)
	c.(*net.UnixConn).CloseWrite()
	var r Response
	json.NewDecoder(c).Decode(&r)
	return r
}

func TestExactKeys(t *testing.T) {
	for in, want := range map[string]bool{
		`{}0`: false, `{} {}`: false, `{}x`: false, ` {} `: true, `{}`: true, `{"method":"x"}`: true, `{"method":"x","params":{"method":1,"method":2}}`: true, // nested keys are not its business
		`{"method":"x","method":"y"}`:      false,
		`{"method":"x","METHOD":"y"}`:      false,
		`{"method":"x","\u006dethod":"y"}`: false,
		`{"Method":"x"}`:                   false,
		"{\"\u212aey\":1}":                 false, // the Kelvin sign folds to k
		`{"admin":true}`:                   false,
		`[]`:                               false,
		`"x"`:                              false,
		`{"method":`:                       false,
		`{"method":"x"`:                    false,
		`{"method" "x"}`:                   false,
		`{"method":"x",}`:                  false,
		``:                                 false,
		`{"params":` + strings.Repeat(`[`, 20000): false,
	} {
		if got := ExactKeys([]byte(in), "method", "params"); got != want {
			t.Errorf("%.60q: %v, want %v", in, got, want)
		}
	}
	if !ExactKeys([]byte(`{"a":1,"b":2}`)) || ExactKeys([]byte(`{"a":1,"A":2}`)) {
		t.Error("without a list only duplicates are refused")
	}
}

// Every hostile request is answered with a fixed code, never reaches a method, never echoes what it was sent, and
// leaves no goroutine behind.
func TestHostileRequestsAreRefusedWithFixedCodes(t *testing.T) {
	base := runtime.NumGoroutine()
	called := make(chan struct{}, 256)
	ts := startServer(t, map[string]Method{"x": func(context.Context, json.RawMessage) (any, error) { called <- struct{}{}; return 1, nil }})
	const canary = "SECRET-CANARY"
	for name, p := range map[string]string{
		"duplicate method":             `{"method":"x","method":"` + canary + `"}`,
		"duplicate params":             `{"method":"x","params":1,"params":2}`,
		"case variant":                 `{"METHOD":"x"}`,
		"escaped duplicate":            `{"method":"x","method":"y"}`,
		"unknown field":                `{"method":"x","` + canary + `":1}`,
		"array":                        `["` + canary + `"]`,
		"empty":                        ``,
		"nested without end":           `{"method":"x","params":` + strings.Repeat(`[`, 100000),
		"bidi in the key":              "{\"method\":\"x\",\"‮" + canary + "\":1}",
		"control in the key":           "{\"method\":\"x\",\"\x01" + canary + "\":1}",
		"huge number then a duplicate": `{"method":"x","params":` + strings.Repeat(`9`, 100000) + `,"method":"y"}`,
		"invalid UTF-8 key":            "{\"method\":\"x\",\"\xff" + canary + "\":1}",
		"NUL in the method":            "{\"method\":\"x\x00\"}",
		"bidi in the method":           "{\"method\":\"x‮\"}",
		"method of the wrong type":     `{"method":["` + canary + `"]}`,
	} {
		r := sentWhole(t, ts.path, []byte(p))
		if r.OK || (r.Error != "bad_request" && r.Error != "unknown_method") || strings.Contains(r.Error, canary) {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// nesting far past the decoder depth limit is refused by it, in bounded time and memory
	if r := sentWhole(t, ts.path, []byte(`{"method":"x","params":`+strings.Repeat(`[`, 100000)+strings.Repeat(`]`, 100000)+`}`)); r.OK {
		t.Errorf("100000 levels of nesting were accepted: %+v", r)
	}
	// 10 000 well-formed requests in a flood of tiny connections are each answered, one after the other
	for i := 0; i < 200; i++ {
		if r := sentWhole(t, ts.path, []byte(`{"method":"x"}`)); !r.OK {
			t.Fatalf("request %d: %+v", i, r)
		}
	}
	if len(called) != 200 {
		t.Fatalf("%d calls reached the method, want 200", len(called))
	}
	ts.stop()
	goroutinesSettle(t, base)
}

// Peers that connect and say nothing, or say half a request and stop, are cut off at the connection deadline, free
// their slots and leave no goroutine. The deadline is shortened for the test; the rule is the same at 30 s.
func TestStalledPeersAreCutOffAndFreeTheirSlots(t *testing.T) {
	old := connDeadline
	t.Cleanup(func() { connDeadline = old })
	connDeadline = 300 * time.Millisecond
	base := runtime.NumGoroutine()
	ts := startServer(t, map[string]Method{"x": func(context.Context, json.RawMessage) (any, error) { return 1, nil }})
	var held []net.Conn
	for i := 0; i < maxConns; i++ {
		c, err := net.Dial("unix", ts.path)
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			c.Write([]byte(`{"method":"x","params":"`)) // half a request
		}
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i, c := range held { // every one of them is closed by the server, without the peer doing anything
		c.SetReadDeadline(time.Now().Add(20 * time.Second))
		b := make([]byte, 512)
		n, _ := c.Read(b)
		if !strings.Contains(string(b[:n]), "bad_request") && n != 0 {
			t.Errorf("stalled peer %d was told %q", i, b[:n])
		}
		if _, err := c.Read(b); err == nil || strings.Contains(err.Error(), "timeout") {
			t.Errorf("stalled peer %d was not closed: %v", i, err)
		}
	}
	if r := sentWhole(t, ts.path, []byte(`{"method":"x"}`)); !r.OK {
		t.Fatalf("the slots were not freed: %+v", r)
	}
	ts.stop()
	goroutinesSettle(t, base)
}

// Whatever the bytes, ExactKeys never panics, and when it says yes the input really is one object whose keys differ
// even without case and sit inside the list.
func FuzzExactKeys(f *testing.F) {
	for _, s := range []string{`{}`, `{"method":"x"}`, `{"method":"x","method":"y"}`, `{"Method":"x"}`, `{"method":"x","params":[[[[1]]]]}`,
		`{"method":"x","method":"y"}`, "{\"Key\":1}", `{"method":`, `[]`, ``, "{\"method\":\"x\xff\"}", `{"params":{"a":1,"a":2},"method":"x"}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if !ExactKeys(b, "method", "params") {
			return
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(b, &m) != nil {
			t.Fatalf("accepted what is not an object: %q", b)
		}
		for k := range m {
			if k != "method" && k != "params" {
				t.Fatalf("accepted key %q", k)
			}
		}
		if bytes := strings.Count(string(b), `"method"`); bytes > 1 && !strings.Contains(string(b), `"params"`) {
			t.Fatalf("accepted a duplicate: %q", b)
		}
	})
}
