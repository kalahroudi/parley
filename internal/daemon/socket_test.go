// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/logx"
)

type testServer struct {
	path string
	log  *syncBuf
	stop func()
}

// syncBuf is a log sink the test can read while the server writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func startServer(t *testing.T, methods map[string]Method) testServer {
	return startServerAs(t, os.Geteuid(), methods)
}

func startServerAs(t *testing.T, uid int, methods map[string]Method) testServer {
	t.Helper()
	path := filepath.Join(shortTemp(t), "s", "d.sock")
	ln, err := listenSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	log := &syncBuf{}
	s := &server{log: logx.New(log), methods: methods, uid: uid}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.serve(ctx, ln); close(done) }()
	stop := func() { cancel(); <-done }
	t.Cleanup(stop)
	return testServer{path, log, stop}
}

func TestSocketMethods(t *testing.T) {
	ts := startServer(t, map[string]Method{
		"echo":      func(_ context.Context, p json.RawMessage) (any, error) { return json.RawMessage(p), nil },
		"deny":      func(context.Context, json.RawMessage) (any, error) { return nil, &RPCError{Code: "not_allowed"} },
		"boom":      func(context.Context, json.RawMessage) (any, error) { return nil, errors.New("secret-task-content") },
		"nomarshal": func(context.Context, json.RawMessage) (any, error) { return make(chan int), nil },
	})
	ctx := context.Background()
	r, err := Call(ctx, ts.path, "echo", map[string]int{"a": 1})
	if err != nil || !r.OK || string(r.Result) != `{"a":1}` {
		t.Fatalf("echo: %+v %v", r, err)
	}
	for method, want := range map[string]string{"deny": "not_allowed", "boom": "internal", "nomarshal": "internal", "missing": "unknown_method"} {
		r, err := Call(ctx, ts.path, method, nil)
		if err != nil || r.OK || r.Error != want {
			t.Errorf("%s: %+v %v, want error %q", method, r, err, want)
		}
	}
	if strings.Contains(ts.log.String(), "secret-task-content") {
		t.Errorf("error text reached the log: %s", ts.log.String())
	}
	if (&RPCError{Code: "x"}).Error() == "" {
		t.Error("RPCError text")
	}
}

func rawRoundTrip(t *testing.T, path string, payload []byte) Response {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write(payload)
	var r Response
	json.NewDecoder(c).Decode(&r)
	return r
}

func TestSocketRejectsMalformedAndOversizedRequests(t *testing.T) {
	ts := startServer(t, map[string]Method{"x": func(context.Context, json.RawMessage) (any, error) { return 1, nil }})
	if r := rawRoundTrip(t, ts.path, []byte("not json")); r.Error != "bad_request" {
		t.Errorf("garbage: %+v", r)
	}
	big := `{"method":"x","params":"` + strings.Repeat("a", maxRequestBytes) + `"}`
	if r := rawRoundTrip(t, ts.path, []byte(big)); r.Error != "bad_request" {
		t.Errorf("oversized: %+v", r)
	}
}

func TestSocketConnectionLimit(t *testing.T) {
	block := make(chan struct{})
	ts := startServer(t, map[string]Method{"hold": func(ctx context.Context, _ json.RawMessage) (any, error) {
		select {
		case <-block:
		case <-ctx.Done():
		}
		return 1, nil
	}})
	var held []net.Conn
	for i := 0; i < maxConns; i++ {
		c, err := net.Dial("unix", ts.path)
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte(`{"method":"hold"}`))
		held = append(held, c)
	}
	waitFor(t, "all slots busy", func() bool {
		// the (maxConns+1)th is accepted by the kernel and then closed by the server
		c, err := net.Dial("unix", ts.path)
		if err != nil {
			return false
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, err = c.Read(make([]byte, 1))
		return err != nil && !os.IsTimeout(err)
	})
	waitFor(t, "refusal logged", func() bool { return strings.Contains(ts.log.String(), "too many open") })
	close(block)
	for _, c := range held {
		c.Close()
	}
}

func TestShutdownClosesOpenConnections(t *testing.T) {
	started := make(chan struct{})
	ts := startServer(t, map[string]Method{"hang": func(ctx context.Context, _ json.RawMessage) (any, error) {
		close(started)
		<-ctx.Done()
		return 1, nil
	}})
	c, _ := net.Dial("unix", ts.path)
	defer c.Close()
	c.Write([]byte(`{"method":"hang"}`))
	<-started
	ts.stop() // must return even though a request is in flight
	if _, err := net.Dial("unix", ts.path); err == nil {
		t.Error("listener still accepting after shutdown")
	}
}

func TestListenSocketRules(t *testing.T) {
	dir := shortTemp(t)
	long := filepath.Join(dir, strings.Repeat("a", maxSocketPath))
	if _, err := listenSocket(long); err == nil {
		t.Error("over-long path accepted")
	}
	// A regular file at the socket path is not removed.
	p := filepath.Join(dir, "p", "d.sock")
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, []byte("keep"), 0o600)
	if _, err := listenSocket(p); err == nil {
		t.Error("a non-socket file was replaced")
	}
	if b, _ := os.ReadFile(p); string(b) != "keep" {
		t.Error("the file was modified")
	}
	// A stale socket left by a crashed daemon is replaced.
	os.Remove(p)
	ln, err := listenSocket(p)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	ln2, err := listenSocket(p)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	ln2.Close()
	// The directory is a file.
	f := filepath.Join(dir, "f")
	os.WriteFile(f, nil, 0o600)
	if _, err := listenSocket(filepath.Join(f, "d.sock")); err == nil {
		t.Error("socket under a file accepted")
	}
}

func TestCallErrors(t *testing.T) {
	if _, err := Call(context.Background(), filepath.Join(shortTemp(t), "none.sock"), "x", nil); err == nil {
		t.Error("no daemon: want error")
	}
	ts := startServer(t, map[string]Method{"x": func(context.Context, json.RawMessage) (any, error) { return 1, nil }})
	if _, err := Call(context.Background(), ts.path, "x", make(chan int)); err == nil {
		t.Error("unmarshalable params: want error")
	}
	// A peer that answers with garbage.
	p := filepath.Join(shortTemp(t), "g.sock")
	ln, _ := net.Listen("unix", p)
	defer ln.Close()
	go func() { c, _ := ln.Accept(); c.Write([]byte("garbage")); c.Close() }()
	if _, err := Call(context.Background(), p, "x", nil); err == nil {
		t.Error("bad reply: want error")
	}
}
