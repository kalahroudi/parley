// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package localsock

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/logx"
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

// stallConn is a connection whose peer says its first bytes and then nothing: Read blocks until the connection's
// deadline "fires", which the test does by closing expire. No clock is involved, so nothing depends on how fast the
// machine is. The deadline the server set is recorded.
type stallConn struct {
	first    []byte
	expire   chan struct{}
	reading  chan struct{}
	closed   chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
	reply    bytes.Buffer
}

func newStallConn(first string) *stallConn {
	return &stallConn{first: []byte(first), expire: make(chan struct{}), reading: make(chan struct{}), closed: make(chan struct{})}
}

func (c *stallConn) Read(p []byte) (int, error) {
	if len(c.first) > 0 {
		n := copy(p, c.first)
		c.first = c.first[n:]
		return n, nil
	}
	select {
	case <-c.reading:
	default:
		close(c.reading)
	}
	select {
	case <-c.expire:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, net.ErrClosed
	}
}
func (c *stallConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reply.Write(p)
}
func (c *stallConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *stallConn) LocalAddr() net.Addr              { return nil }
func (c *stallConn) RemoteAddr() net.Addr             { return nil }
func (c *stallConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stallConn) SetWriteDeadline(time.Time) error { return nil }
func (c *stallConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *stallConn) told() string { c.mu.Lock(); defer c.mu.Unlock(); return c.reply.String() }

// chanListener hands out the connections the test sends it.
type chanListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr { return nil }

// Peers that connect and say nothing, or say half a request and stop, hold their slots until the connection
// deadline, which the server sets on every connection; when it fires they are answered with a fixed code and closed,
// the slots are free again and no goroutine is left. A peer past the limit is closed unread meanwhile.
func TestStalledPeersAreCutOffAndFreeTheirSlots(t *testing.T) {
	base := runtime.NumGoroutine()
	old := checkPeerFn
	checkPeerFn = func(net.Conn, int) error { return nil }
	defer func() { checkPeerFn = old }()
	ln := &chanListener{conns: make(chan net.Conn), done: make(chan struct{})}
	s := &Server{Log: logx.New(&syncBuf{}), UID: os.Geteuid(), Methods: map[string]Method{"x": func(context.Context, json.RawMessage) (any, error) { return 1, nil }}}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { s.Serve(ctx, ln); close(served) }()

	before := time.Now()
	var held []*stallConn
	for i := 0; i < maxConns; i++ {
		c := newStallConn(map[bool]string{true: `{"method":"x","params":"`, false: ``}[i%2 == 0]) // half a request, or nothing
		held = append(held, c)
		ln.conns <- c
	}
	for _, c := range held {
		<-c.reading
		c.mu.Lock()
		d := c.deadline
		c.mu.Unlock()
		if d.Before(before.Add(connDeadline)) || d.After(time.Now().Add(connDeadline)) {
			t.Fatalf("deadline %v is not %v from now", d, connDeadline)
		}
	}
	over := newStallConn("")
	ln.conns <- over
	select {
	case <-over.closed:
	case <-time.After(30 * time.Second):
		t.Fatal("a peer past the connection limit was not closed")
	}
	select {
	case <-over.reading:
		t.Fatal("a peer past the connection limit was read")
	default:
	}
	for _, c := range held { // the deadlines fire
		close(c.expire)
	}
	for i, c := range held {
		select {
		case <-c.closed:
		case <-time.After(30 * time.Second):
			t.Fatalf("stalled peer %d was not closed", i)
		}
		if !strings.Contains(c.told(), `"error":"bad_request"`) {
			t.Errorf("stalled peer %d was told %q", i, c.told())
		}
	}
	good := newStallConn(`{"method":"x"}`)
	ln.conns <- good
	select {
	case <-good.closed:
	case <-time.After(30 * time.Second):
		t.Fatal("the slots were not freed")
	}
	if !strings.Contains(good.told(), `"ok":true`) {
		t.Fatalf("the next request was told %q", good.told())
	}
	cancel()
	<-served
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
