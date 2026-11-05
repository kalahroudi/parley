// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package bot

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// Defaults for Config: five running, five waiting (the plan's "queue 5 then
// reject"), the longest a bot may take, and how long a bot gets to return once
// its context has ended before Host stops waiting for it.
const (
	DefaultMaxRunning = 5
	DefaultMaxQueued  = 5
	DefaultTimeout    = time.Duration(900e9) // 15 minutes
	DefaultGrace      = time.Duration(5e9)   // 5 seconds
	sendTimeout       = time.Duration(30e9)  // 30 seconds
)

// Responder sends the bot's messages to the caller; *pipeline.Node is one.
type Responder interface {
	Respond(ctx context.Context, id [16]byte, typ envelope.Type, content []byte) error
}

// Config sets a Host's limits. Zero values take the defaults (MaxQueued: a
// negative value means no queue).
type Config struct {
	Bot        Bot
	Responder  Responder
	MaxRunning int
	MaxQueued  int
	Timeout    time.Duration // longest a task may run, also bounded by its expiry
	Grace      time.Duration // how long a bot may take to return after its context ended
	Now        func() time.Time
}

// Host runs a Bot for the pipeline. Wire Inbound as pipeline.Config.OnInbound.
type Host struct {
	cfg  Config
	base context.Context
	stop context.CancelFunc
	sem  chan struct{}
	wg   sync.WaitGroup

	mu     sync.Mutex
	tasks  map[[16]byte]*run
	live   int // running plus queued
	closed bool
}

type run struct {
	cancel   context.CancelFunc
	replies  chan []byte
	canceled bool // CANCEL from the caller: the final message is its acknowledgment
}

// NewHost builds a Host. Close it when the daemon stops.
func NewHost(cfg Config) (*Host, error) {
	if cfg.Bot == nil || cfg.Responder == nil {
		return nil, ErrConfig
	}
	if cfg.MaxRunning <= 0 {
		cfg.MaxRunning = DefaultMaxRunning
	}
	if cfg.MaxQueued < 0 {
		cfg.MaxQueued = 0
	} else if cfg.MaxQueued == 0 {
		cfg.MaxQueued = DefaultMaxQueued
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Grace <= 0 {
		cfg.Grace = DefaultGrace
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	base, stop := context.WithCancel(context.Background())
	return &Host{cfg: cfg, base: base, stop: stop, sem: make(chan struct{}, cfg.MaxRunning), tasks: map[[16]byte]*run{}}, nil
}

// Inbound is pipeline.Config.OnInbound. It returns at once: tasks run on their
// own goroutines, and Content is copied before it returns.
func (h *Host) Inbound(in pipeline.Inbound) {
	switch in.Type {
	case envelope.TypeTask:
		h.start(in)
	case envelope.TypeReply:
		h.mu.Lock()
		r := h.tasks[in.TaskID]
		h.mu.Unlock()
		if r != nil {
			select {
			case r.replies <- append([]byte(nil), in.Content...):
			default: // no question is waiting: the pipeline's state check should have refused this
			}
		}
	case envelope.TypeCancel:
		h.mu.Lock()
		r := h.tasks[in.TaskID]
		if r != nil {
			r.canceled = true
		}
		h.mu.Unlock()
		if r != nil {
			r.cancel()
		} else {
			// Nothing runs (it finished, or never started): acknowledge so the caller's wait ends.
			h.send(in.TaskID, envelope.TypeCancel, nil)
		}
	}
}

func (h *Host) start(in pipeline.Inbound) {
	h.mu.Lock()
	if h.tasks[in.TaskID] != nil {
		// Already ours. An answer here would end the live task, so say nothing.
		h.mu.Unlock()
		return
	}
	if h.live >= h.cfg.MaxRunning+h.cfg.MaxQueued || h.closed {
		h.mu.Unlock()
		h.send(in.TaskID, envelope.TypeError, []byte(TextBusy))
		return
	}
	deadline := h.cfg.Now().Add(h.cfg.Timeout)
	if !in.Expiry.IsZero() && in.Expiry.Before(deadline) {
		deadline = in.Expiry
	}
	ctx, cancel := context.WithDeadline(h.base, deadline)
	r := &run{cancel: cancel, replies: make(chan []byte, 1)}
	h.tasks[in.TaskID] = r
	h.live++
	h.wg.Add(1)
	h.mu.Unlock()
	t := Task{ID: in.TaskID, Context: in.Context, Caller: in.Caller, Owner: in.Owner, Expiry: in.Expiry,
		Content: append([]byte(nil), in.Content...)}
	go h.exec(ctx, r, t)
}

func (h *Host) exec(ctx context.Context, r *run, t Task) {
	defer h.wg.Done()
	defer func() {
		h.mu.Lock()
		delete(h.tasks, t.ID)
		h.live--
		h.mu.Unlock()
		r.cancel()
	}()
	select {
	case h.sem <- struct{}{}:
	case <-ctx.Done():
		clear(t.Content)
		h.finish(ctx, r, t.ID, nil, nil)
		return
	}
	if ctx.Err() != nil { // both were ready: an ended task never reaches the bot
		<-h.sem
		clear(t.Content)
		h.finish(ctx, r, t.ID, nil, nil)
		return
	}
	s := &session{h: h, ctx: ctx, id: t.ID, r: r}
	res, err, returned := h.call(ctx, t, s)
	s.close()
	if returned { // otherwise the bot ignored its context and keeps its slot and buffer until it returns
		<-h.sem
		clear(t.Content) // before the caller can see the final message
	}
	h.finish(ctx, r, t.ID, res, err)
}

// call runs the bot on its own goroutine and contains its panic or Goexit: what
// it panicked with is dropped. When the context has ended and the bot has not
// returned within Config.Grace, call stops waiting (returned is false) and the
// slot and buffer are released by the goroutine that is still running the bot.
func (h *Host) call(ctx context.Context, t Task, s Session) (res []byte, err error, returned bool) {
	type outcome struct {
		res []byte
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		o := outcome{err: &Failure{Message: TextFailed}} // what a panic or Goexit leaves
		defer func() {
			if recover() != nil {
				o = outcome{err: &Failure{Message: TextFailed}}
			}
			done <- o
		}()
		o.res, o.err = h.cfg.Bot.Handle(ctx, t, s)
	}()
	select {
	case o := <-done:
		return o.res, o.err, true
	case <-ctx.Done():
	}
	grace := time.NewTimer(h.cfg.Grace)
	defer grace.Stop()
	select {
	case o := <-done:
		return o.res, o.err, true
	case <-grace.C:
	}
	go func() {
		<-done
		clear(t.Content)
		<-h.sem
	}()
	return nil, nil, false
}

// finish sends the task's one final message.
func (h *Host) finish(ctx context.Context, r *run, id [16]byte, res []byte, err error) {
	h.mu.Lock()
	canceled := r.canceled
	h.mu.Unlock()
	if canceled {
		h.send(id, envelope.TypeCancel, nil)
		return
	}
	if h.base.Err() != nil {
		return // shutting down: the daemon is going away and the caller's task fails by expiry
	}
	if err == nil && ctx.Err() == nil {
		if len(res) > pipeline.MaxContent {
			h.send(id, envelope.TypeError, []byte(TextTooLarge))
		} else if h.send(id, envelope.TypeResult, res) != nil {
			h.send(id, envelope.TypeError, []byte(TextFailed)) // a failed send leaves the task open: end it
		}
		return
	}
	if ctx.Err() == context.DeadlineExceeded {
		h.send(id, envelope.TypeError, []byte(TextTimedOut))
		return
	}
	msg := TextFailed
	var f *Failure
	if errors.As(err, &f) && f != nil && f.Message != "" {
		msg = strings.ToValidUTF8(f.Message[:min(len(f.Message), MaxFailure)], "")
		if msg == "" {
			msg = TextFailed
		}
	}
	h.send(id, envelope.TypeError, []byte(msg))
}

func (h *Host) send(id [16]byte, typ envelope.Type, content []byte) error {
	ctx, cancel := context.WithTimeout(h.base, sendTimeout)
	defer cancel()
	return h.cfg.Responder.Respond(ctx, id, typ, content)
}

// Close cancels every task, waits for the bots to return (at most Config.Grace
// for one that ignores its context) and stops accepting new ones. Tasks cut off
// this way send nothing: the caller's task expires.
func (h *Host) Close() {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	h.stop()
	h.wg.Wait()
}

type session struct {
	h   *Host
	ctx context.Context // the task's: ends on cancel, expiry, timeout and Close
	id  [16]byte
	r   *run

	mu     sync.Mutex
	closed bool
}

func (s *session) close() { s.mu.Lock(); s.closed = true; s.mu.Unlock() }

func (s *session) open() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return nil
}

// respond sends under a context that ends with the bot's, the task's or the
// send timeout, whichever is first.
func (s *session) respond(ctx context.Context, typ envelope.Type, content []byte) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	defer context.AfterFunc(s.ctx, cancel)()
	return s.h.cfg.Responder.Respond(ctx, s.id, typ, content)
}

func (s *session) Status(ctx context.Context, text []byte) error {
	if err := s.open(); err != nil {
		return err
	}
	return s.respond(ctx, envelope.TypeStatus, text)
}

func (s *session) Ask(ctx context.Context, question []byte) ([]byte, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	if err := s.respond(ctx, envelope.TypeInputRequired, question); err != nil {
		return nil, err
	}
	select {
	case a := <-s.r.replies:
		return a, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
