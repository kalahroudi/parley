// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeGateway implements the Device DO side of the protocol in memory.
type fakeGateway struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	session  string // empty: none yet
	rxSeq    uint64
	txSeq    uint64
	got      []string // bodies accepted, in order
	conns    []*websocket.Conn
	hellos   []map[string]any
	dials    int
	failAuth bool
	welcome  func(resumed bool) map[string]any // optional override
}

func newFakeGateway(t *testing.T) *fakeGateway {
	g := &fakeGateway{t: t}
	g.srv = httptest.NewServer(http.HandlerFunc(g.handle))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGateway) url() string { return "ws" + strings.TrimPrefix(g.srv.URL, "http") }

func (g *fakeGateway) handle(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.dials++
	fail := g.failAuth
	g.mu.Unlock()
	if fail || r.Header.Get("Authorization") != "Bearer tok" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	ctx := r.Context()
	_, data, err := c.Read(ctx)
	if err != nil {
		return
	}
	var h map[string]any
	_ = json.Unmarshal(data, &h)
	g.mu.Lock()
	g.hellos = append(g.hellos, h)
	resumed := g.session != "" && h["session"] == g.session
	if !resumed {
		g.session, g.rxSeq, g.txSeq = "s"+time.Now().Format("150405.000000"), 0, 0
	}
	wel := map[string]any{"t": "welcome", "v": 1, "session": g.session, "resumed": resumed, "rx_seq": g.rxSeq, "heartbeat_ms": 50}
	if g.welcome != nil {
		wel = g.welcome(resumed)
	}
	g.mu.Unlock()
	b, _ := json.Marshal(wel)
	_ = c.Write(ctx, websocket.MessageText, b)
	// Registered only once the welcome is on the wire, so a push can never overtake
	// it (the client rejects an event before the welcome).
	g.mu.Lock()
	g.conns = append(g.conns, c)
	g.mu.Unlock()
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		if string(data) == "ping" {
			_ = c.Write(ctx, websocket.MessageText, []byte("pong"))
			continue
		}
		var m struct {
			T    string `json:"t"`
			Seq  uint64 `json:"seq"`
			Body string `json:"body"`
		}
		_ = json.Unmarshal(data, &m)
		if m.T != "frame" {
			continue
		}
		g.mu.Lock()
		if m.Seq > g.rxSeq {
			g.rxSeq = m.Seq
			g.got = append(g.got, m.Body)
		}
		g.mu.Unlock()
		ack, _ := json.Marshal(map[string]any{"t": "ack", "seq": m.Seq})
		_ = c.Write(ctx, websocket.MessageText, ack)
	}
}

// push sends an event with an explicit seq to the newest connection.
func (g *fakeGateway) push(seq uint64, body string) {
	g.mu.Lock()
	c := g.conns[len(g.conns)-1]
	g.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"t": "event", "seq": seq, "body": body})
	_ = c.Write(context.Background(), websocket.MessageText, b)
}

// drop abruptly closes every connection.
func (g *fakeGateway) drop() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, c := range g.conns {
		c.CloseNow()
	}
	g.conns = nil
}

func (g *fakeGateway) received() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.got...)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func start(t *testing.T, g *fakeGateway, mod func(*Config)) (*Client, context.CancelFunc, chan error) {
	t.Helper()
	cfg := Config{URL: g.url(), Token: "tok", MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond, HeartbeatTimeout: time.Second}
	if mod != nil {
		mod(&cfg)
	}
	c := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx); close(done) }() // closed, so tests that read the error can still be cleaned up
	t.Cleanup(func() { cancel(); <-done })
	return c, cancel, done
}

func TestSendAndAck(t *testing.T) {
	g := newFakeGateway(t)
	c, _, _ := start(t, g, nil)
	for _, b := range []string{"a", "b", "c"} {
		if err := c.Send(b); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "frames", func() bool { return len(g.received()) == 3 })
	waitFor(t, "acks", func() bool { c.mu.Lock(); defer c.mu.Unlock(); return len(c.outbox) == 0 })
	if got := strings.Join(g.received(), ""); got != "abc" {
		t.Fatalf("got %q", got)
	}
}

func TestEventsDedupedAndAcked(t *testing.T) {
	g := newFakeGateway(t)
	c, _, _ := start(t, g, nil)
	waitFor(t, "connect", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.conns) == 1 })
	g.push(1, "x")
	g.push(1, "x") // duplicate
	g.push(2, "y")
	var got []Event
	for len(got) < 2 {
		select {
		case e := <-c.Events():
			got = append(got, e)
		case <-time.After(5 * time.Second):
			t.Fatal("no event")
		}
	}
	if got[0] != (Event{1, "x"}) || got[1] != (Event{2, "y"}) {
		t.Fatalf("got %v", got)
	}
	select {
	case e := <-c.Events():
		t.Fatalf("duplicate delivered: %v", e)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestReconnectResumesWithoutLossOrDuplicates(t *testing.T) {
	g := newFakeGateway(t)
	var states []bool
	var smu sync.Mutex
	c, _, _ := start(t, g, func(cfg *Config) {
		cfg.OnState = func(b bool) { smu.Lock(); states = append(states, b); smu.Unlock() }
	})
	const total = 200
	go func() {
		for i := 0; i < total; i++ {
			_ = c.Send(string(rune('A'+i%26)) + "-" + itoa(i))
			time.Sleep(200 * time.Microsecond)
		}
	}()
	for i := 0; i < 20; i++ {
		waitFor(t, "connection", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.conns) > 0 })
		g.drop()
		time.Sleep(3 * time.Millisecond)
	}
	waitFor(t, "all frames", func() bool { return len(g.received()) == total })
	for i, b := range g.received() {
		if !strings.HasSuffix(b, "-"+itoa(i)) {
			t.Fatalf("frame %d out of order or duplicated: %q", i, b)
		}
	}
	g.mu.Lock()
	hellos := len(g.hellos)
	resumed := g.hellos[hellos-1]["session"]
	g.mu.Unlock()
	if hellos < 2 || resumed == nil {
		t.Fatalf("expected resume hellos, got %d (last session %v)", hellos, resumed)
	}
	smu.Lock()
	defer smu.Unlock()
	if len(states) < 4 {
		t.Fatalf("states %v", states)
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestLostSessionResetsEventNumbering(t *testing.T) {
	g := newFakeGateway(t)
	c, _, _ := start(t, g, nil)
	waitFor(t, "connect", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.conns) == 1 })
	g.push(1, "x")
	g.push(2, "y")
	<-c.Events()
	<-c.Events()
	g.mu.Lock()
	g.session = "" // the gateway forgets the session (e.g. storage wiped)
	g.mu.Unlock()
	g.drop()
	waitFor(t, "reconnect", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.conns) == 1 })
	g.push(1, "fresh")
	select {
	case e := <-c.Events():
		if e.Body != "fresh" {
			t.Fatalf("got %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event after session loss was dropped as a duplicate")
	}
}

func TestResumeSendsSessionAndLastRx(t *testing.T) {
	g := newFakeGateway(t)
	c, _, _ := start(t, g, nil)
	waitFor(t, "connect", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.conns) == 1 })
	g.push(1, "x")
	<-c.Events()
	g.drop()
	waitFor(t, "second hello", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.hellos) == 2 })
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.hellos[0]["session"] != nil || g.hellos[0]["last_rx"] != float64(0) {
		t.Fatalf("first hello %v", g.hellos[0])
	}
	if g.hellos[1]["session"] != g.session || g.hellos[1]["last_rx"] != float64(1) {
		t.Fatalf("second hello %v", g.hellos[1])
	}
}

func TestRefusedCredentialsStopRun(t *testing.T) {
	g := newFakeGateway(t)
	g.failAuth = true
	_, _, done := start(t, g, nil)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "credentials") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept retrying a refused credential")
	}
}

func TestHelloErrorStopsRun(t *testing.T) {
	g := newFakeGateway(t)
	g.welcome = func(bool) map[string]any { return map[string]any{"t": "error", "code": "bad_message"} }
	_, _, done := start(t, g, nil)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "bad_message") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept retrying")
	}
}

func TestUnexpectedFirstMessageReconnects(t *testing.T) {
	g := newFakeGateway(t)
	g.welcome = func(bool) map[string]any { return map[string]any{"t": "ack", "seq": 1} }
	start(t, g, nil)
	waitFor(t, "retries", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return g.dials >= 3 })
}

func TestHeartbeatTimeoutReconnects(t *testing.T) {
	g := newFakeGateway(t)
	// Gateway answers hello but never pongs: replace handler behavior via a silent server.
	silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		_, _, _ = c.Read(r.Context())
		_ = c.Write(r.Context(), websocket.MessageText, []byte(`{"t":"welcome","v":1,"session":"s","resumed":false,"rx_seq":0,"heartbeat_ms":10}`))
		<-r.Context().Done()
	}))
	defer silent.Close()
	_ = g
	var mu sync.Mutex
	var states []bool
	c := New(Config{URL: "ws" + strings.TrimPrefix(silent.URL, "http"), Token: "tok", MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, HeartbeatTimeout: 30 * time.Millisecond,
		OnState: func(b bool) { mu.Lock(); states = append(states, b); mu.Unlock() }})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "reconnect after silence", func() bool { mu.Lock(); defer mu.Unlock(); return len(states) >= 4 })
}

func TestSendAfterRunReturnsAndLimits(t *testing.T) {
	g := newFakeGateway(t)
	c, cancel, done := start(t, g, nil)
	if err := c.Send(strings.Repeat("x", maxFrameBytes)); err == nil {
		t.Fatal("oversized frame accepted")
	}
	// Under the raw limit, but quotes double in JSON and push it over.
	if err := c.Send(strings.Repeat(`"`, maxFrameBytes/2+1)); err == nil {
		t.Fatal("frame that exceeds the limit once encoded accepted")
	}
	cancel()
	<-done
	if err := c.Send("late"); err != ErrClosed {
		t.Fatalf("err = %v", err)
	}
	if _, ok := <-c.Events(); ok {
		t.Fatal("Events not closed")
	}
}

func TestBackoffBounds(t *testing.T) {
	for attempt := 0; attempt < 12; attempt++ {
		for i := 0; i < 50; i++ {
			d := backoff(100*time.Millisecond, time.Second, attempt)
			if d < 50*time.Millisecond || d > time.Second {
				t.Fatalf("attempt %d: %v", attempt, d)
			}
		}
	}
	if d := backoff(time.Second, time.Second, 5); d < 500*time.Millisecond || d > time.Second {
		t.Fatalf("capped: %v", d)
	}
}

// Regression: connect must wait for both loops. A readLoop that outlived connect
// could send on Events after Run closed it (a panic) or into the next connection.
// The seam holds the readLoop just before delivery while the client shuts down.
func TestRunWaitsForReadLoop(t *testing.T) {
	for i := 0; i < 12; i++ {
		g := newFakeGateway(t)
		entered := make(chan struct{}, 1)
		c := New(Config{URL: g.url(), Token: "tok", MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond, HeartbeatTimeout: time.Second})
		c.beforeDeliver = func() {
			select {
			case entered <- struct{}{}:
			default:
			}
			time.Sleep(50 * time.Millisecond)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		waitFor(t, "connect", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.conns) > 0 })
		g.push(1, "e")
		<-entered
		cancel()
		<-done
		// Without the fix the held readLoop now sends on the closed Events channel.
		time.Sleep(100 * time.Millisecond)
	}
}

func TestNewFillsDefaults(t *testing.T) {
	c := New(Config{})
	if c.cfg.HeartbeatTimeout != 10*time.Second || c.cfg.MinBackoff != 250*time.Millisecond || c.cfg.MaxBackoff != 30*time.Second {
		t.Fatalf("defaults: %+v", c.cfg)
	}
	// A max below the min is replaced, not honored.
	c = New(Config{MinBackoff: time.Second, MaxBackoff: time.Millisecond})
	if c.cfg.MaxBackoff != 30*time.Second {
		t.Fatalf("max backoff %v", c.cfg.MaxBackoff)
	}
}

func TestRunWithCanceledContextReturnsAtOnce(t *testing.T) {
	c := New(Config{URL: "ws://127.0.0.1:1", Token: "tok"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, open := <-c.Events(); open {
		t.Fatal("Events left open")
	}
}

// A dial that fails without an HTTP response (nothing is listening) is retried.
func TestDialFailureRetries(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	url := "ws" + strings.TrimPrefix(dead.URL, "http")
	dead.Close()
	c := New(Config{URL: url, Token: "tok", MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() { cancel(); <-done }()
	// Run keeps going: it is still alive after several backoff periods.
	select {
	case err := <-done:
		t.Fatalf("Run stopped: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

// A connection that closes before the welcome is retried.
func TestCloseBeforeWelcomeReconnects(t *testing.T) {
	var mu sync.Mutex
	dials := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		mu.Lock()
		dials++
		mu.Unlock()
		_, _, _ = c.Read(r.Context())
		c.CloseNow()
	}))
	defer srv.Close()
	c := New(Config{URL: "ws" + strings.TrimPrefix(srv.URL, "http"), Token: "tok", MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "retries", func() bool { mu.Lock(); defer mu.Unlock(); return dials >= 3 })
}

// pushRaw sends an arbitrary text message to the newest connection.
func (g *fakeGateway) pushRaw(msg string) {
	g.mu.Lock()
	c := g.conns[len(g.conns)-1]
	g.mu.Unlock()
	_ = c.Write(context.Background(), websocket.MessageText, []byte(msg))
}

// A gateway error message or a message that is not JSON ends the connection,
// and the client reconnects and carries on.
func TestBadGatewayMessagesReconnect(t *testing.T) {
	for name, msg := range map[string]string{"error": `{"t":"error","code":"overloaded"}`, "not json": "{"} {
		g := newFakeGateway(t)
		start(t, g, nil)
		waitFor(t, name+": connected", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.conns) == 1 })
		g.pushRaw(msg)
		waitFor(t, name+": reconnect", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.hellos) >= 2 })
	}
}

// Without heartbeat_ms in the welcome the client uses its default period and still works.
func TestWelcomeWithoutHeartbeatUsesDefault(t *testing.T) {
	g := newFakeGateway(t)
	g.welcome = func(bool) map[string]any {
		return map[string]any{"t": "welcome", "v": 1, "session": "s", "resumed": false, "rx_seq": 0}
	}
	c, _, _ := start(t, g, nil)
	waitFor(t, "connected", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.conns) == 1 })
	g.push(1, "hello")
	select {
	case ev := <-c.Events():
		if ev.Body != "hello" {
			t.Fatalf("got %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
}

// A half-open link: the gateway keeps sending, the client hears nothing (the seam used by
// the real-Worker soak). Events sent into it are lost and acknowledgements never arrive;
// once the link is heard again, later events are delivered.
func TestDeafLinkDiscardsGatewayMessages(t *testing.T) {
	g := newFakeGateway(t)
	var deaf atomic.Bool
	c := New(Config{URL: g.url(), Token: "tok", MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond, HeartbeatTimeout: time.Second})
	c.deaf = deaf.Load
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "connection", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.conns) > 0 })

	deaf.Store(true)
	g.push(1, "lost")
	if err := c.Send("unheard-ack"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "frame reached the gateway", func() bool { return len(g.received()) == 1 })
	select {
	case e := <-c.Events():
		t.Fatalf("a deaf client delivered %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
	c.mu.Lock()
	unacked := len(c.outbox)
	c.mu.Unlock()
	if unacked != 1 {
		t.Fatalf("outbox = %d, want 1: the ack was heard", unacked)
	}

	deaf.Store(false)
	g.push(2, "heard")
	select {
	case e := <-c.Events():
		if e.Body != "heard" {
			t.Fatalf("got %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event not delivered after the link was heard again")
	}
}
