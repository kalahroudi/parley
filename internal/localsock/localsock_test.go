// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package localsock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
	path := filepath.Join(tempDir(t), "s", "d.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	log := &syncBuf{}
	s := &Server{Log: logx.New(log), Methods: methods, UID: uid}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Serve(ctx, ln); close(done) }()
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
	started, release := make(chan struct{}), make(chan struct{})
	ts := startServer(t, map[string]Method{"hang": func(context.Context, json.RawMessage) (any, error) {
		close(started)
		<-release // not the context: the connection must be closed by the shutdown sweep itself
		return 1, nil
	}})
	c, _ := net.Dial("unix", ts.path)
	defer c.Close()
	c.Write([]byte(`{"method":"hang"}`))
	<-started
	stopped := make(chan struct{})
	go func() { ts.stop(); close(stopped) }()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || os.IsTimeout(err) {
		t.Errorf("the open connection was not closed by shutdown: %v", err)
	}
	close(release)
	<-stopped // must return even though a request was in flight
	if _, err := net.Dial("unix", ts.path); err == nil {
		t.Error("listener still accepting after shutdown")
	}
}

func TestListenSocketRules(t *testing.T) {
	dir := tempDir(t)
	long := filepath.Join(dir, strings.Repeat("a", MaxPath))
	if _, err := Listen(long); err == nil {
		t.Error("over-long path accepted")
	}
	// A regular file at the socket path is not removed.
	p := filepath.Join(dir, "p", "d.sock")
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, []byte("keep"), 0o600)
	if _, err := Listen(p); err == nil {
		t.Error("a non-socket file was replaced")
	}
	if b, _ := os.ReadFile(p); string(b) != "keep" {
		t.Error("the file was modified")
	}
	// A stale socket left by a crashed daemon is replaced.
	os.Remove(p)
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	ln2, err := Listen(p)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	ln2.Close()
	// The directory is a file.
	f := filepath.Join(dir, "f")
	os.WriteFile(f, nil, 0o600)
	if _, err := Listen(filepath.Join(f, "d.sock")); err == nil {
		t.Error("socket under a file accepted")
	}
}

func TestCallErrors(t *testing.T) {
	if _, err := Call(context.Background(), filepath.Join(tempDir(t), "none.sock"), "x", nil); err == nil {
		t.Error("no daemon: want error")
	}
	ts := startServer(t, map[string]Method{"x": func(context.Context, json.RawMessage) (any, error) { return 1, nil }})
	if _, err := Call(context.Background(), ts.path, "x", make(chan int)); err == nil {
		t.Error("unmarshalable params: want error")
	}
	// A peer that answers with garbage.
	p := filepath.Join(tempDir(t), "g.sock")
	ln, _ := net.Listen("unix", p)
	defer ln.Close()
	go func() { c, _ := ln.Accept(); c.Write([]byte("garbage")); c.Close() }()
	if _, err := Call(context.Background(), p, "x", nil); err == nil {
		t.Error("bad reply: want error")
	}
}

// tempDir returns a short private temp directory: unix socket paths are limited
// to about 104 bytes and t.TempDir paths on macOS are too long.
func tempDir(t *testing.T) string {
	t.Helper()
	// Unix socket paths are limited to about 104 bytes (the daemon allows 100) and
	// a runner's TMPDIR can be much longer, so use /tmp where there is one.
	base := ""
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat("/tmp"); err == nil && fi.IsDir() {
			base = "/tmp"
		}
	}
	d, err := os.MkdirTemp(base, "ls")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if len(d) > 70 {
		t.Fatalf("temp directory %q is too long for a socket path under it (%d characters, at most 70); set TMPDIR to a short directory", d, len(d))
	}
	return d
}

// noCloseListener hides Close so a test can make Accept return a connection
// after the server's shutdown sweep has already run.
type noCloseListener struct{ net.Listener }

func (noCloseListener) Close() error { return nil }

func TestConnectionAcceptedAfterShutdownIsClosed(t *testing.T) {
	ln, err := Listen(filepath.Join(tempDir(t), "s", "d.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // shutdown has begun, and its sweep of open connections is over
	s := &Server{Log: logx.New(&syncBuf{}), UID: os.Geteuid()}
	done := make(chan struct{})
	go func() { s.Serve(ctx, noCloseListener{ln}); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return: a connection accepted during shutdown was left open")
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || os.IsTimeout(err) {
		t.Errorf("the connection accepted during shutdown was not closed: %v", err)
	}
}

func TestListenRefusesRelativePath(t *testing.T) {
	for _, p := range []string{"@abstract", "@abstract/parleyd.sock", "rel/parleyd.sock"} {
		if _, err := Listen(p); err == nil {
			t.Errorf("Listen(%q) accepted a non-absolute path", p)
		}
	}
}

func TestListenFailures(t *testing.T) {
	boom := errors.New("boom")
	p := filepath.Join(tempDir(t), "s", "d.sock")
	oldListen := listenUnix
	listenUnix = func(string) (net.Listener, error) { return nil, boom }
	if _, err := Listen(p); !errors.Is(err, boom) {
		t.Errorf("listen failure: %v", err)
	}
	listenUnix = oldListen

	// A stale socket that cannot be removed.
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	oldRemove := removeFile
	removeFile = func(string) error { return boom }
	if _, err := Listen(p); !errors.Is(err, boom) {
		t.Errorf("stale socket removal failure: %v", err)
	}
	removeFile = oldRemove
}

func TestAcceptErrorsAreRetriedWithoutSpinning(t *testing.T) {
	ln := &flakyListener{done: make(chan struct{})}
	s := &Server{Log: logx.New(&syncBuf{}), UID: os.Geteuid()}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() { s.Serve(ctx, ln); close(finished) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-finished
	// With a 10ms pause after each failure there are about ten attempts in 100ms;
	// a loop with no pause makes many thousands.
	if n := ln.calls.Load(); n < 2 || n > 40 {
		t.Errorf("%d accept attempts in 100ms", n)
	}
}

// flakyListener fails every Accept with a transient error until it is closed.
type flakyListener struct {
	calls atomic.Int32
	done  chan struct{}
	once  sync.Once
}

func (f *flakyListener) Accept() (net.Conn, error) {
	f.calls.Add(1)
	select {
	case <-f.done:
		return nil, net.ErrClosed
	default:
		return nil, errors.New("transient")
	}
}
func (f *flakyListener) Close() error   { f.once.Do(func() { close(f.done) }); return nil }
func (f *flakyListener) Addr() net.Addr { return nil }

// failingConn fails every write.
type failingConn struct{ net.Conn }

func (failingConn) Write([]byte) (int, error)   { return 0, errors.New("write failed") }
func (failingConn) SetDeadline(time.Time) error { return nil }
func (failingConn) Close() error                { return nil }

func TestCallWriteFailure(t *testing.T) {
	old := dialUnix
	dialUnix = func(context.Context, string) (net.Conn, error) { return failingConn{}, nil }
	defer func() { dialUnix = old }()
	if _, err := Call(context.Background(), "x", "m", nil); err == nil {
		t.Error("a failed write must be an error")
	}
}

func TestCallHonoursAnEarlierCallerDeadline(t *testing.T) {
	p := filepath.Join(tempDir(t), "h.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { c, _ := ln.Accept(); time.Sleep(2 * time.Second); c.Close() }() // never answers
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Call(ctx, p, "x", nil); err == nil {
		t.Error("a silent daemon must time out")
	}
	if time.Since(start) > time.Second {
		t.Errorf("the caller's deadline was ignored: %v", time.Since(start))
	}
}

func TestCallSendsMethodAndParams(t *testing.T) {
	ts := startServer(t, map[string]Method{"echo": func(_ context.Context, p json.RawMessage) (any, error) { return json.RawMessage(p), nil }})
	r, err := Call(context.Background(), ts.path, "echo", []int{1, 2})
	if err != nil || !r.OK || string(r.Result) != "[1,2]" {
		t.Errorf("%+v %v", r, err)
	}
	r, err = Call(context.Background(), ts.path, "echo", nil)
	if err != nil || !r.OK || string(r.Result) != "null" {
		t.Errorf("no params: %+v %v", r, err)
	}
}

// Constant expressions have no statement for a mutant to be covered by; the
// limits are pinned here.
func TestConstantsArePinned(t *testing.T) {
	if MaxPath != 100 || maxRequestBytes != 256<<10 || maxReplyBytes != 4<<20 || connDeadline != 30*time.Second || acceptRetry != 10*time.Millisecond || maxConns != 32 {
		t.Error("a limit changed")
	}
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestListenAcceptsPathsUpToTheLimit(t *testing.T) {
	dir := tempDir(t) + string(filepath.Separator)
	fill := func(n int) string { return dir + strings.Repeat("a", n-len(dir)) }
	ln, err := Listen(fill(MaxPath))
	if err != nil {
		t.Fatalf("a path of exactly %d characters: %v", MaxPath, err)
	}
	ln.Close()
	if _, err := Listen(fill(MaxPath + 1)); err == nil {
		t.Errorf("a path of %d characters was accepted", MaxPath+1)
	}
}

// scriptedListener returns the scripted Accept results, then blocks until closed.
type scriptedListener struct {
	script []func() (net.Conn, error)
	next   int
	done   chan struct{}
	once   sync.Once
}

func (s *scriptedListener) Accept() (net.Conn, error) {
	if s.next < len(s.script) {
		f := s.script[s.next]
		s.next++
		return f()
	}
	<-s.done
	return nil, net.ErrClosed
}
func (s *scriptedListener) Close() error   { s.once.Do(func() { close(s.done) }); return nil }
func (s *scriptedListener) Addr() net.Addr { return nil }

func TestServeEndsWhenTheListenerIsClosedUnderIt(t *testing.T) {
	s := &Server{Log: logx.New(&syncBuf{}), UID: os.Geteuid()}
	ln := &scriptedListener{script: []func() (net.Conn, error){func() (net.Conn, error) { return nil, net.ErrClosed }}, done: make(chan struct{})}
	finished := make(chan struct{})
	go func() { s.Serve(context.Background(), ln); close(finished) }() // ctx is never cancelled
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept accepting on a closed listener")
	}
}

func TestServeEndsOnAnyAcceptErrorOnceShuttingDown(t *testing.T) {
	s := &Server{Log: logx.New(&syncBuf{}), UID: os.Geteuid()}
	ctx, cancel := context.WithCancel(context.Background())
	ln := &scriptedListener{script: []func() (net.Conn, error){func() (net.Conn, error) {
		cancel()
		return nil, errors.New("some other failure")
	}}, done: make(chan struct{})}
	finished := make(chan struct{})
	go func() { s.Serve(ctx, ln); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept accepting after shutdown began")
	}
}

func TestListenRestrictFailure(t *testing.T) {
	old := restrictFn
	restrictFn = func(string) error { return errors.New("boom") }
	defer func() { restrictFn = old }()
	p := filepath.Join(tempDir(t), "s", "d.sock")
	if _, err := Listen(p); err == nil {
		t.Fatal("a socket that could not be restricted must not be served")
	}
	if _, err := net.Dial("unix", p); err == nil {
		t.Error("the unrestricted listener was left open")
	}
}

// A refused peer is closed and logged, and later connections are still served.
func TestRefusedPeerDoesNotStopTheServer(t *testing.T) {
	var calls atomic.Int32
	old := checkPeerFn
	checkPeerFn = func(net.Conn, int) error {
		if calls.Add(1) == 1 {
			return errors.New("not this user")
		}
		return nil
	}
	path := filepath.Join(tempDir(t), "s", "d.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	log := &syncBuf{}
	s := &Server{Log: logx.New(log), UID: os.Geteuid(), Methods: map[string]Method{"x": func(context.Context, json.RawMessage) (any, error) { return 1, nil }}}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() { s.Serve(ctx, ln); close(finished) }()
	defer func() { cancel(); <-finished; checkPeerFn = old }()
	if r, err := Call(context.Background(), path, "x", nil); err == nil && r.OK {
		t.Error("the refused connection was served")
	}
	if r, err := Call(context.Background(), path, "x", nil); err != nil || !r.OK {
		t.Errorf("a refused connection must not stop later ones being served: %+v %v", r, err)
	}
	waitFor(t, "refusal logged", func() bool { return strings.Contains(log.String(), "not this user") })
}

func TestHandlerContextHasTheConnectionDeadline(t *testing.T) {
	got := make(chan time.Duration, 1)
	ts := startServer(t, map[string]Method{"x": func(ctx context.Context, _ json.RawMessage) (any, error) {
		dl, ok := ctx.Deadline()
		if !ok {
			got <- -1
		} else {
			got <- time.Until(dl)
		}
		return 1, nil
	}})
	if _, err := Call(context.Background(), ts.path, "x", nil); err != nil {
		t.Fatal(err)
	}
	if d := <-got; d <= 0 || d > connDeadline {
		t.Errorf("handler deadline %v, want within (0, %v]", d, connDeadline)
	}
}

// 32 KiB of control characters is 192 KiB of JSON in a request; 512 KiB of them
// (the largest directory page) is 3 MiB in a reply. Both must fit.
func TestEscapedMaximumRequestAndLargeReplyRoundTrip(t *testing.T) {
	ts := startServer(t, map[string]Method{"x": func(_ context.Context, p json.RawMessage) (any, error) {
		var s struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(p, &s); err != nil {
			return nil, err
		}
		return strings.Repeat("\x01", 512<<10) + s.Text[:1], nil
	}})
	r, err := Call(context.Background(), ts.path, "x", map[string]string{"text": strings.Repeat("\x01", 32<<10)})
	if err != nil || !r.OK {
		t.Fatalf("%+v %v", r, err)
	}
	var s string
	if json.Unmarshal(r.Result, &s) != nil || len(s) != 512<<10+1 {
		t.Errorf("reply length %d", len(s))
	}
}
