// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package bot

import (
	"context"
	"sync"
	"time"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// Defaults for Config: five running, five waiting (the plan's "queue 5 then
// reject"), and the longest a bot may take.
const (
	DefaultMaxRunning = 5
	DefaultMaxQueued  = 5
	DefaultTimeout    = 15 * time.Minute
	sendTimeout       = 30 * time.Second
)

// Responder sends the bot's messages to the caller; *pipeline.Node is one.
type Responder interface {
	Respond(ctx context.Context, id [16]byte, typ envelope.Type, content []byte) error
}

// Config sets a Host's limits. Zero values take the defaults.
type Config struct {
	Bot        Bot
	Responder  Responder
	MaxRunning int
	MaxQueued  int
	Timeout    time.Duration // longest a task may run, also bounded by its expiry
	Now        func() time.Time
}

// Host runs a Bot for the pipeline. Wire Inbound as pipeline.Config.OnInbound.
type Host struct {
	cfg  Config
	base context.Context
	stop context.CancelFunc
	sem  chan struct{}
	wg   sync.WaitGroup

	mu    sync.Mutex
	tasks map[[16]byte]*run
	live  int // running plus queued
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
	if h.tasks[in.TaskID] != nil || h.live >= h.cfg.MaxRunning+h.cfg.MaxQueued || h.base.Err() != nil {
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
	defer clear(t.Content)
	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	case <-ctx.Done():
		h.finish(ctx, r, t.ID, nil, nil)
		return
	}
	s := &session{h: h, id: t.ID, r: r}
	res, err := h.call(ctx, t, s)
	s.close()
	clear(t.Content) // before the caller can see the final message
	h.finish(ctx, r, t.ID, res, err)
}

// call runs the bot and contains its panic: what it panicked with is dropped.
func (h *Host) call(ctx context.Context, t Task, s Session) (res []byte, err error) {
	defer func() {
		if recover() != nil {
			res, err = nil, &Failure{Message: TextFailed}
		}
	}()
	return h.cfg.Bot.Handle(ctx, t, s)
}

// finish sends the task's one final message.
func (h *Host) finish(ctx context.Context, r *run, id [16]byte, res []byte, err error) {
	h.mu.Lock()
	canceled := r.canceled
	h.mu.Unlock()
	switch {
	case canceled:
		h.send(id, envelope.TypeCancel, nil)
	case h.base.Err() != nil:
		// Shutting down: the daemon is going away and the caller's task fails by expiry.
	case err == nil && ctx.Err() == nil:
		if h.send(id, envelope.TypeResult, res) != nil {
			h.send(id, envelope.TypeError, []byte(TextTooLarge))
		}
	case ctx.Err() == context.DeadlineExceeded:
		h.send(id, envelope.TypeError, []byte(TextTimedOut))
	default:
		msg := TextFailed
		if f, ok := err.(*Failure); ok && f.Message != "" {
			msg = f.Message
			if len(msg) > MaxFailure {
				msg = msg[:MaxFailure]
			}
		}
		h.send(id, envelope.TypeError, []byte(msg))
	}
}

func (h *Host) send(id [16]byte, typ envelope.Type, content []byte) error {
	ctx, cancel := context.WithTimeout(h.base, sendTimeout)
	defer cancel()
	return h.cfg.Responder.Respond(ctx, id, typ, content)
}

// Close cancels every task, waits for the bots to return and stops accepting
// new ones. Tasks cut off this way send nothing: the caller's task expires.
func (h *Host) Close() {
	h.stop()
	h.wg.Wait()
}

type session struct {
	h  *Host
	id [16]byte
	r  *run

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

func (s *session) Status(ctx context.Context, text []byte) error {
	if err := s.open(); err != nil {
		return err
	}
	return s.h.cfg.Responder.Respond(ctx, s.id, envelope.TypeStatus, text)
}

func (s *session) Ask(ctx context.Context, question []byte) ([]byte, error) {
	if err := s.open(); err != nil {
		return nil, err
	}
	if err := s.h.cfg.Responder.Respond(ctx, s.id, envelope.TypeInputRequired, question); err != nil {
		return nil, err
	}
	select {
	case a := <-s.r.replies:
		return a, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
