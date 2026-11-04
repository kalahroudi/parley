// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package supervisor runs the daemon's background components (the tunnel
// client, the revocation refresh) and restarts them with jittered, growing
// delays. It decides nothing about content: states and counts only, no error
// text, so a failing component cannot leak through the status or the log.
package supervisor

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/kalahroudi/parley/internal/logx"
)

// ErrShutdownTimeout means a component did not stop within the shutdown budget.
var ErrShutdownTimeout = errors.New("supervisor: a component did not stop in time")

// Component states reported by Status.
const (
	StateRunning = "running"
	StateBackoff = "backoff"
	StateStopped = "stopped"
)

// Component is one background job. Run should block until ctx ends; if it
// fails or panics the supervisor restarts it after a jittered, growing delay.
// A nil return while ctx is live means the component finished for good.
type Component struct {
	Name       string // an identifier (letters, digits, - and _)
	Run        func(ctx context.Context) error
	MaxBackoff time.Duration // zero means 30s
}

// ComponentStatus is the supervisor's view of one component. It carries no
// error text: errors can embed content, so only counts and states are kept.
type ComponentStatus struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Restarts int    `json:"restarts"`
}

// Supervisor runs components and restarts them. It is safe for concurrent use.
type Supervisor struct {
	Log        *logx.Logger
	MinBackoff time.Duration // zero means 250ms
	// ShutdownTimeout bounds how long Run waits for components after ctx ends. Zero means 10s.
	ShutdownTimeout time.Duration

	// Test seams: the clock, the random source and the wait between restarts.
	now   func() time.Time
	rnd   func(n int64) int64
	sleep func(ctx context.Context, d time.Duration) bool

	mu     sync.Mutex
	status map[string]*ComponentStatus
	order  []string
}

func (s *Supervisor) set(name string, f func(*ComponentStatus)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s.status[name])
}

// Status returns a snapshot in start order.
func (s *Supervisor) Status() []ComponentStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ComponentStatus, 0, len(s.order))
	for _, n := range s.order {
		out = append(out, *s.status[n])
	}
	return out
}

// Run starts every component and blocks until ctx ends and all have stopped,
// or ShutdownTimeout passes (ErrShutdownTimeout).
func (s *Supervisor) Run(ctx context.Context, comps ...Component) error {
	s.mu.Lock()
	s.status = map[string]*ComponentStatus{}
	s.order = nil
	for _, c := range comps {
		s.status[c.Name] = &ComponentStatus{Name: c.Name, State: StateBackoff}
		s.order = append(s.order, c.Name)
	}
	s.mu.Unlock()

	var wg sync.WaitGroup
	for _, c := range comps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.supervise(ctx, c)
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	<-ctx.Done()
	t := time.NewTimer(s.budget())
	defer t.Stop()
	select {
	case <-done:
		return nil
	case <-t.C:
		return ErrShutdownTimeout
	}
}

const (
	// Written as single literals (nanoseconds): a product such as 30 * time.Second
	// has no statement for the mutation gate to cover. TestConstantsArePinned pins them.
	defaultMinBackoff = time.Duration(250_000_000)    // 250ms
	defaultMaxBackoff = time.Duration(30_000_000_000) // 30s
	defaultShutdown   = time.Duration(10_000_000_000) // 10s
)

func (s *Supervisor) budget() time.Duration {
	if s.ShutdownTimeout <= 0 {
		return defaultShutdown
	}
	return s.ShutdownTimeout
}

func (s *Supervisor) bounds(c Component) (minB, maxB time.Duration) {
	minB, maxB = s.MinBackoff, c.MaxBackoff
	if minB <= 0 {
		minB = defaultMinBackoff
	}
	if maxB <= 0 {
		maxB = defaultMaxBackoff
	}
	return minB, maxB
}

func (s *Supervisor) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Supervisor) pause(ctx context.Context, d time.Duration) bool {
	if s.sleep != nil {
		return s.sleep(ctx, d)
	}
	return sleepCtx(ctx, d)
}

// jitter returns d scaled by 0.5..1.0 so restarts across devices do not align.
func (s *Supervisor) jitter(d time.Duration) time.Duration {
	n := rand.Int64N
	if s.rnd != nil {
		n = s.rnd
	}
	return d/2 + time.Duration(n(int64(d/2)+1))
}

func (s *Supervisor) supervise(ctx context.Context, c Component) {
	minB, maxB := s.bounds(c)
	delay := minB
	defer s.set(c.Name, func(st *ComponentStatus) { st.State = StateStopped })
	for ctx.Err() == nil {
		s.set(c.Name, func(st *ComponentStatus) { st.State = StateRunning })
		start := s.clock()
		err, panicked := runRecover(ctx, c.Run)
		if ctx.Err() != nil {
			return
		}
		if err == nil && !panicked {
			s.Log.Info("component finished", logx.ID("component", c.Name))
			return
		}
		// Neither the error nor the panic value is logged: either can carry content.
		s.Log.Warn("component failed, restarting", logx.ID("component", c.Name))
		s.set(c.Name, func(st *ComponentStatus) { st.State = StateBackoff; st.Restarts++ })
		if s.clock().Sub(start) > maxB { // it ran a good while: start the backoff over
			delay = minB
		}
		if !s.pause(ctx, s.jitter(delay)) {
			return
		}
		delay = min(delay*2, maxB)
	}
}

func runRecover(ctx context.Context, f func(context.Context) error) (err error, panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	return f(ctx), false
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
