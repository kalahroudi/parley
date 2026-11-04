// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package outbox is the sender-side wait for an offline target. The gateway
// never queues task ciphertext, so a caller's daemon holds the pending task in
// memory, watches the target's presence, and only when the target is connected
// asks it for a one-time prekey and sends (the Send hook does both). It gives up
// at the task's expiry and the task is FAILED. Nothing is written to disk and
// nothing is sent while waiting: a restart of the caller's daemon fails every
// pending task: its status is then unknown, which the caller must report as FAILED and resend. At most PerTarget wait for one target and MaxWaiting in all.
package outbox

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

var (
	// ErrRecipientOffline is the failure for a target that stayed offline until the task expired.
	ErrRecipientOffline = errors.New("outbox: recipient offline until the task expired")
	// ErrGone means the target no longer exists or is hidden from this caller. A
	// Presence or Send hook returns an error wrapping it to end the wait at once.
	ErrGone = errors.New("outbox: recipient not found")
	// ErrOffline is returned by the Send hook when the target dropped between the
	// presence check and the send (no prekey, or the relay says offline). The wait goes on.
	ErrOffline = errors.New("outbox: recipient went offline")
	// ErrClosed fails a task that was still waiting when the outbox closed.
	ErrClosed = errors.New("outbox: closed")

	ErrFull        = errors.New("outbox: too many tasks waiting")
	ErrTargetFull  = errors.New("outbox: too many tasks waiting for this recipient")
	ErrDuplicate   = errors.New("outbox: task already waiting")
	ErrInvalid     = errors.New("outbox: invalid task")
	ErrExpired     = errors.New("outbox: task already expired")
	ErrUnknown     = errors.New("outbox: no such task")
	ErrSending     = errors.New("outbox: task is being sent, cancel it at the gateway once it is sent")
	ErrAlreadySent = errors.New("outbox: task already sent, cancel it at the gateway")
)

// Limits. MaxExpiry is the plan's longest task expiry.
const (
	MaxExpiry          = 24 * time.Hour
	DefaultMaxWaiting  = 64
	DefaultPerTarget   = 16
	DefaultMaxFinished = 1024
	DefaultKeepDone    = 15 * time.Minute
	DefaultMinPoll     = time.Second
	DefaultMaxPoll     = 15 * time.Second
)

// Task is what the outbox needs to know: the card to watch, and the deadline.
type Task struct {
	ID     string    // the task id, at most 64 bytes
	Target string    // opaque to the outbox: what Presence takes (the card id)
	Expiry time.Time // the task expiry, at most MaxExpiry from now
}

// State is where a task is, from the sender's side.
type State uint8

const (
	Waiting  State = iota + 1 // the target is offline: "waiting for recipient"
	Sending                   // online: asking for a prekey and sending
	Sent                      // handed to the gateway, whose task state is the truth from here
	Failed                    // never sent; Status.Err says why
	Canceled                  // canceled before it was sent; the target never heard of it
)

// Status is a task's state, and for Failed the reason.
type Status struct {
	State State
	Err   error
}

// a2aStates maps a task the gateway has not seen yet onto the gateway's state
// names (src/a2a.ts): waiting is SUBMITTED, as it is once the gateway has the
// task. Sent is absent on purpose: from there the gateway's Task DO is the truth.
var a2aStates = map[State]string{
	Waiting:  "TASK_STATE_SUBMITTED",
	Sending:  "TASK_STATE_SUBMITTED",
	Failed:   "TASK_STATE_FAILED",
	Canceled: "TASK_STATE_CANCELED",
}

// A2AState is the state in the gateway's vocabulary, or "" once Sent.
func (s Status) A2AState() string { return a2aStates[s.State] }

// Config wires the outbox. Presence and Send are required; the rest have defaults.
type Config struct {
	// Presence reports whether the target is connected. An error that has a
	// RetryAfter() time.Duration method (the gateway's rate limit) is waited out;
	// one wrapping ErrGone fails the task; any other error is retried with backoff.
	Presence func(ctx context.Context, target string) (bool, error)
	// Send asks the target for a prekey and sends the sealed task. nil means
	// sent; an error wrapping ErrOffline means keep waiting (it must mean the
	// gateway did not deliver the task: that is what keeps a task from running
	// twice); any other error (refused, not permitted, prekey rejected) fails
	// the task. The outbox calls Send for one task at most once at a time and
	// never again after it returned nil or a failure.
	Send func(ctx context.Context, t Task) error

	MaxWaiting  int           // all tasks waiting at once, zero means DefaultMaxWaiting
	PerTarget   int           // tasks waiting for one target, zero means DefaultPerTarget
	MaxFinished int           // finished tasks remembered, zero means DefaultMaxFinished
	KeepDone    time.Duration // how long, zero means DefaultKeepDone
	MinPoll     time.Duration // first wait between presence checks, doubled up to MaxPoll
	MaxPoll     time.Duration

	// Test seams.
	Now    func() time.Time
	Sleep  func(ctx context.Context, d time.Duration) error // nil error after d, or the context's error
	Jitter func(d time.Duration) time.Duration
}

type entry struct {
	task   Task
	start  time.Time       // when it was submitted
	ttl    time.Duration   // time from start to the expiry, so a wall clock that jumps cannot stretch the wait
	ctx    context.Context // ended when the task finishes, so a canceled task's goroutine stops at once
	stop   context.CancelFunc
	status Status
	done   chan struct{}
	at     time.Time // when it reached a final state
}

// Outbox holds pending tasks in memory.
type Outbox struct {
	cfg    Config
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	tasks   map[string]*entry
	waiting int
	perTgt  map[string]int // waiting tasks by target
	closed  bool
}

// New returns an Outbox. Close it to fail what is still waiting and stop its goroutines.
func New(cfg Config) (*Outbox, error) {
	if cfg.Presence == nil || cfg.Send == nil {
		return nil, errors.New("outbox: Presence and Send are required")
	}
	if cfg.MaxWaiting <= 0 {
		cfg.MaxWaiting = DefaultMaxWaiting
	}
	if cfg.PerTarget <= 0 {
		cfg.PerTarget = DefaultPerTarget
	}
	if cfg.MaxFinished <= 0 {
		cfg.MaxFinished = DefaultMaxFinished
	}
	if cfg.KeepDone <= 0 {
		cfg.KeepDone = DefaultKeepDone
	}
	if cfg.MinPoll <= 0 {
		cfg.MinPoll = DefaultMinPoll
	}
	if cfg.MaxPoll < cfg.MinPoll {
		cfg.MaxPoll = max(DefaultMaxPoll, cfg.MinPoll)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleep
	}
	if cfg.Jitter == nil {
		cfg.Jitter = jitter
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Outbox{cfg: cfg, ctx: ctx, cancel: cancel, tasks: map[string]*entry{}, perTgt: map[string]int{}}, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// jitter spreads checks by up to a quarter, so tasks waiting on the same target
// do not all hit the gateway together when it comes back from a deploy.
func jitter(d time.Duration) time.Duration {
	return d + time.Duration(rand.Int64N(int64(d)/4+1))
}

// Submit starts waiting for the target. It returns at once.
func (o *Outbox) Submit(t Task) error {
	now := o.cfg.Now()
	if t.ID == "" || len(t.ID) > 64 || t.Target == "" || t.Expiry.After(now.Add(MaxExpiry)) {
		return ErrInvalid
	}
	if !t.Expiry.After(now) {
		return ErrExpired
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return ErrClosed
	}
	if o.tasks[t.ID] != nil {
		return ErrDuplicate
	}
	if o.waiting >= o.cfg.MaxWaiting {
		return ErrFull
	}
	if o.perTgt[t.Target] >= o.cfg.PerTarget {
		return ErrTargetFull
	}
	o.prune(now)
	ectx, stop := context.WithCancel(o.ctx)
	e := &entry{task: t, start: now, ttl: t.Expiry.Sub(now), ctx: ectx, stop: stop, status: Status{State: Waiting}, done: make(chan struct{})}
	o.perTgt[t.Target]++
	o.tasks[t.ID] = e
	o.waiting++
	o.wg.Add(1)
	go o.run(e)
	return nil
}

// prune forgets finished tasks that are old, then the oldest ones past the cap.
// Called with mu held.
func (o *Outbox) prune(now time.Time) {
	finished := 0
	var oldest *entry
	for id, e := range o.tasks {
		if e.at.IsZero() {
			continue
		}
		if now.Sub(e.at) >= o.cfg.KeepDone {
			delete(o.tasks, id)
			continue
		}
		finished++
		if oldest == nil || e.at.Before(oldest.at) {
			oldest = e
		}
	}
	if finished >= o.cfg.MaxFinished {
		delete(o.tasks, oldest.task.ID)
	}
}

// Status is a task's state, or false if unknown (never submitted, or forgotten).
func (o *Outbox) Status(id string) (Status, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	e := o.tasks[id]
	if e == nil {
		return Status{}, false
	}
	return e.status, true
}

// Done is closed when the task reaches Sent, Failed or Canceled (or is unknown).
func (o *Outbox) Done(id string) <-chan struct{} {
	o.mu.Lock()
	defer o.mu.Unlock()
	if e := o.tasks[id]; e != nil {
		return e.done
	}
	c := make(chan struct{})
	close(c)
	return c
}

// Cancel stops waiting for a task that has not been sent; after that, cancel it at the gateway.
func (o *Outbox) Cancel(id string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	e := o.tasks[id]
	if e == nil {
		return ErrUnknown
	}
	if e.status.State == Sending {
		return ErrSending
	}
	if e.status.State == Sent {
		return ErrAlreadySent
	}
	if e.status.State == Waiting {
		o.finish(e, Status{State: Canceled})
	} // already Failed or Canceled: canceling again is fine
	return nil
}

// Close fails every task still waiting and waits for the goroutines to end.
func (o *Outbox) Close() {
	o.mu.Lock()
	o.closed = true
	o.mu.Unlock()
	o.cancel()
	o.wg.Wait()
}

// finish records the final state. Called with mu held, once per task.
func (o *Outbox) finish(e *entry, s Status) {
	e.status = s
	e.at = o.cfg.Now()
	o.waiting--
	if o.perTgt[e.task.Target]--; o.perTgt[e.task.Target] == 0 {
		delete(o.perTgt, e.task.Target)
	}
	e.stop()
	close(e.done)
}

// begin moves a waiting task to Sending; it reports false if the task was
// canceled in the meantime.
func (o *Outbox) begin(e *entry) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if e.status.State != Waiting {
		return false
	}
	e.status.State = Sending
	return true
}

func (o *Outbox) canceled(e *entry) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return e.status.State != Waiting
}

func (o *Outbox) settle(e *entry, s Status) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if e.status.State == Waiting || e.status.State == Sending {
		o.finish(e, s)
	}
}

// retryAfter is the wait a rate-limited gateway asked for, if err is one.
func retryAfter(err error) (time.Duration, bool) {
	var r interface{ RetryAfter() time.Duration }
	if errors.As(err, &r) {
		return r.RetryAfter(), true
	}
	return 0, false
}

func (o *Outbox) run(e *entry) {
	defer o.wg.Done()
	t := e.task
	poll := o.cfg.MinPoll
	for {
		if o.canceled(e) {
			return
		}
		left := e.ttl - o.cfg.Now().Sub(e.start)
		if left <= 0 {
			o.settle(e, Status{State: Failed, Err: ErrRecipientOffline})
			return
		}
		wait := o.cfg.Jitter(poll)
		online, err := o.cfg.Presence(e.ctx, t.Target)
		if o.ctx.Err() != nil {
			o.settle(e, Status{State: Failed, Err: ErrClosed})
			return
		}
		if errors.Is(err, ErrGone) {
			o.settle(e, Status{State: Failed, Err: err})
			return
		}
		if err != nil {
			if d, ok := retryAfter(err); ok {
				wait = max(d, o.cfg.MinPoll) // a zero or negative hint must not turn the wait into a spin
			}
		} else if online {
			if !o.begin(e) {
				return
			}
			sctx, cancel := context.WithTimeout(e.ctx, left)
			err := o.cfg.Send(sctx, t)
			cancel()
			if err == nil {
				o.settle(e, Status{State: Sent})
				return
			}
			if o.ctx.Err() != nil {
				o.settle(e, Status{State: Failed, Err: ErrClosed})
				return
			}
			if !errors.Is(err, ErrOffline) {
				o.settle(e, Status{State: Failed, Err: fmt.Errorf("send: %w", err)})
				return
			}
			o.reopen(e)
		}
		if err := o.cfg.Sleep(e.ctx, min(wait, left)); err != nil {
			o.settle(e, Status{State: Failed, Err: ErrClosed})
			return
		}
		poll = min(poll*2, o.cfg.MaxPoll)
	}
}

// reopen puts a task whose send found the target offline back to waiting.
func (o *Outbox) reopen(e *entry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	e.status.State = Waiting
}
