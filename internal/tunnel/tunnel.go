// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package tunnel is the daemon's outbound WSS connection to its Device DO.
// It reconnects with jittered backoff and resumes the session: frames the
// gateway has not acknowledged are retransmitted in order, and events are
// de-duplicated by sequence number, so a dropped connection or a gateway
// deploy loses and duplicates nothing. Bodies are opaque to this package.
//
// The wire protocol is defined in gateway/src/protocol.ts.
package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	protocolVersion = 1
	maxFrameBytes   = 1 << 20
)

// ErrClosed is returned by Send after Run has returned.
var ErrClosed = errors.New("tunnel: closed")

// Event is an opaque message pushed by the gateway.
type Event struct {
	Seq  uint64
	Body string
}

// ErrRefused is what a TokenSource returns when the gateway will not issue a token (the device is not bound or
// was revoked): retrying cannot succeed, so Run stops and the daemon's supervisor decides when to try again.
var ErrRefused = errors.New("tunnel: credentials refused")

// Config configures a Client. URL and one of Token and TokenSource are required.
type Config struct {
	URL   string // ws:// or wss:// URL of /v1/connect
	Token string // sent as "Authorization: Bearer <Token>"
	// TokenSource, if set, supplies the token for each connection attempt instead of Token. Device connect tokens
	// are short-lived and checked when the connection opens, so a reconnect after a drop needs a fresh one. An
	// error is retried with backoff, except one wrapping ErrRefused, which stops Run.
	TokenSource func(ctx context.Context) (string, error)

	// HeartbeatTimeout bounds how long a connection may stay silent after a ping.
	// Zero means 10s. Pings go out at the interval the gateway announces.
	HeartbeatTimeout time.Duration
	// MinBackoff and MaxBackoff bound reconnect delay (defaults 250ms and 30s).
	MinBackoff, MaxBackoff time.Duration
	// OnState, if set, is called with true after each welcome and false on disconnect.
	OnState func(connected bool)
}

type outFrame struct {
	Seq  uint64
	Body string
}

// Client maintains one resumable tunnel. Create it with New and call Run.
type Client struct {
	cfg           Config
	events        chan Event
	beforeDeliver func()      // test seam: called before an event is handed to Events
	deaf          func() bool // test seam: while it returns true, gateway messages are discarded unread (a half-open link)
	wake          chan struct{}

	mu      sync.Mutex
	closed  bool
	session string
	lastRx  uint64     // highest event seq delivered to Events
	nextSeq uint64     // last frame seq assigned
	outbox  []outFrame // unacknowledged frames, ascending seq
}

// New returns a Client. Events are delivered on Events(); the consumer must drain it.
func New(cfg Config) *Client {
	if cfg.HeartbeatTimeout <= 0 {
		cfg.HeartbeatTimeout = 10 * time.Second
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = 250 * time.Millisecond
	}
	if cfg.MaxBackoff < cfg.MinBackoff {
		cfg.MaxBackoff = 30 * time.Second
	}
	return &Client{cfg: cfg, events: make(chan Event, 64), wake: make(chan struct{}, 1)}
}

// Events returns the stream of gateway events, in order, without duplicates.
func (c *Client) Events() <-chan Event { return c.events }

// Send queues a frame. It is retransmitted across reconnects until the gateway
// acknowledges it. A restart of the daemon loses queued frames by design.
func (c *Client) Send(body string) error {
	// Size the encoded frame: JSON escaping can inflate a body well past its raw
	// length, and a frame the gateway rejects would be retransmitted forever.
	enc, err := json.Marshal(map[string]any{"t": "frame", "seq": uint64(1<<63 - 1), "body": body})
	if err != nil || len(enc) > maxFrameBytes {
		return errors.New("tunnel: frame too large")
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	c.nextSeq++
	c.outbox = append(c.outbox, outFrame{c.nextSeq, body})
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return nil
}

// Run connects and reconnects until ctx is canceled, then closes Events.
func (c *Client) Run(ctx context.Context) error {
	defer func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.events)
	}()
	attempt := 0
	for ctx.Err() == nil {
		welcomed, err := c.connect(ctx)
		if welcomed {
			attempt = 0
		}
		if ctx.Err() != nil {
			return nil
		}
		var fatal *fatalError
		if errors.As(err, &fatal) {
			return fatal
		}
		if !sleep(ctx, backoff(c.cfg.MinBackoff, c.cfg.MaxBackoff, attempt)) {
			return nil
		}
		attempt++
	}
	return nil
}

// fatalError stops the reconnect loop: retrying cannot succeed.
type fatalError struct{ msg string }

func (e *fatalError) Error() string { return "tunnel: " + e.msg }

func backoff(minD, maxD time.Duration, attempt int) time.Duration {
	d := minD
	for i := 0; i < attempt && d < maxD; i++ {
		d *= 2
	}
	if d > maxD {
		d = maxD
	}
	// Full jitter over the upper half, so a fleet reconnecting after a deploy spreads out.
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

type serverMsg struct {
	T           string `json:"t"`
	Seq         uint64 `json:"seq"`
	Body        string `json:"body"`
	Session     string `json:"session"`
	Resumed     bool   `json:"resumed"`
	RxSeq       uint64 `json:"rx_seq"`
	HeartbeatMS int64  `json:"heartbeat_ms"`
	Code        string `json:"code"`
}

// connect runs one connection to completion. welcomed reports whether the
// handshake succeeded (so the caller resets its backoff).
func (c *Client) connect(ctx context.Context) (welcomed bool, err error) {
	token := c.cfg.Token
	if c.cfg.TokenSource != nil {
		if token, err = c.cfg.TokenSource(ctx); err != nil {
			if errors.Is(err, ErrRefused) {
				return false, &fatalError{"gateway refused credentials"}
			}
			return false, errors.New("tunnel: no connect token")
		}
	}
	dialCtx, cancelDial := context.WithTimeout(ctx, 15*time.Second)
	conn, resp, err := websocket.Dial(dialCtx, c.cfg.URL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	cancelDial()
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return false, &fatalError{"gateway refused credentials"}
		}
		return false, err
	}
	conn.SetReadLimit(maxFrameBytes)
	defer conn.CloseNow()

	c.mu.Lock()
	hello := map[string]any{"t": "hello", "v": protocolVersion, "last_rx": c.lastRx}
	if c.session != "" {
		hello["session"] = c.session
	}
	c.mu.Unlock()
	if err := writeJSON(ctx, conn, hello); err != nil {
		return false, err
	}

	var w serverMsg
	if err := readJSON(ctx, conn, c.cfg.HeartbeatTimeout, &w); err != nil {
		return false, err
	}
	if w.T == "error" {
		return false, &fatalError{"gateway rejected hello: " + w.Code}
	}
	if w.T != "welcome" {
		return false, errors.New("tunnel: expected welcome")
	}
	c.mu.Lock()
	if !w.Resumed {
		// The gateway lost the session: its event numbering restarts.
		c.lastRx = 0
	}
	c.session = w.Session
	c.pruneLocked(w.RxSeq)
	c.mu.Unlock()
	if c.cfg.OnState != nil {
		c.cfg.OnState(true)
		defer c.cfg.OnState(false)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 2)
	hb := time.Duration(w.HeartbeatMS) * time.Millisecond
	if hb <= 0 {
		hb = 20 * time.Second
	}
	go func() { errc <- c.writeLoop(ctx, conn, hb) }()
	go func() { errc <- c.readLoop(ctx, conn, hb+c.cfg.HeartbeatTimeout) }()
	err = <-errc
	cancel()
	conn.Close(websocket.StatusNormalClosure, "")
	// Wait for the other loop too: a leftover readLoop could otherwise deliver to
	// Events after the next connection starts, or after Run has closed it.
	<-errc
	return true, err
}

// pruneLocked drops frames the gateway has already accepted.
func (c *Client) pruneLocked(acked uint64) {
	i := 0
	for i < len(c.outbox) && c.outbox[i].Seq <= acked {
		i++
	}
	c.outbox = c.outbox[i:]
}

// writeLoop sends every unacknowledged frame once per connection, in order,
// then new frames as they are queued, plus heartbeat pings.
func (c *Client) writeLoop(ctx context.Context, conn *websocket.Conn, hb time.Duration) error {
	var sent uint64 // highest seq written on this connection
	tick := time.NewTicker(hb)
	defer tick.Stop()
	for {
		c.mu.Lock()
		var batch []outFrame
		for _, f := range c.outbox {
			if f.Seq > sent {
				batch = append(batch, f)
			}
		}
		c.mu.Unlock()
		for _, f := range batch {
			if err := writeJSON(ctx, conn, map[string]any{"t": "frame", "seq": f.Seq, "body": f.Body}); err != nil {
				return err
			}
			sent = f.Seq
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.wake:
		case <-tick.C:
			wctx, cancel := context.WithTimeout(ctx, c.cfg.HeartbeatTimeout)
			err := conn.Write(wctx, websocket.MessageText, []byte("ping"))
			cancel()
			if err != nil {
				return err
			}
		}
	}
}

// readLoop handles gateway messages. Any message counts as liveness, and the
// read deadline is a full heartbeat period plus the timeout.
func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn, idle time.Duration) error {
	for {
		rctx, cancel := context.WithTimeout(ctx, idle)
		typ, data, err := conn.Read(rctx)
		cancel()
		if err != nil {
			return err
		}
		if typ != websocket.MessageText || string(data) == "pong" {
			continue
		}
		if c.deaf != nil && c.deaf() {
			continue
		}
		var m serverMsg
		if err := json.Unmarshal(data, &m); err != nil {
			return err
		}
		switch m.T {
		case "ack":
			c.mu.Lock()
			c.pruneLocked(m.Seq)
			c.mu.Unlock()
		case "event":
			c.mu.Lock()
			dup := m.Seq <= c.lastRx
			if !dup {
				c.lastRx = m.Seq
			}
			c.mu.Unlock()
			if dup {
				continue
			}
			if c.beforeDeliver != nil {
				c.beforeDeliver()
			}
			select {
			case c.events <- Event{Seq: m.Seq, Body: m.Body}:
			case <-ctx.Done():
				return ctx.Err()
			}
			if err := writeJSON(ctx, conn, map[string]any{"t": "ack", "seq": m.Seq}); err != nil {
				return err
			}
		case "error":
			return errors.New("tunnel: gateway error: " + m.Code)
		}
	}
}

func writeJSON(ctx context.Context, conn *websocket.Conn, v any) error {
	b, err := json.Marshal(v)
	//cover:ignore every value passed here is a map of strings and integers, which always marshals
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return conn.Write(wctx, websocket.MessageText, b)
}

func readJSON(ctx context.Context, conn *websocket.Conn, d time.Duration, v any) error {
	rctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	_, data, err := conn.Read(rctx)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
