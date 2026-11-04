// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/kalahroudi/parley/internal/logx"
)

// ErrShutdownTimeout means a component did not stop within the shutdown budget.
var ErrShutdownTimeout = errors.New("daemon: a component did not stop in time")

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
	budget := s.ShutdownTimeout
	if budget <= 0 {
		budget = 10 * time.Second
	}
	t := time.NewTimer(budget)
	defer t.Stop()
	select {
	case <-done:
		return nil
	case <-t.C:
		return ErrShutdownTimeout
	}
}

func (s *Supervisor) supervise(ctx context.Context, c Component) {
	minB, maxB := s.MinBackoff, c.MaxBackoff
	if minB <= 0 {
		minB = 250 * time.Millisecond
	}
	if maxB <= 0 {
		maxB = 30 * time.Second
	}
	delay := minB
	for ctx.Err() == nil {
		s.set(c.Name, func(st *ComponentStatus) { st.State = StateRunning })
		start := time.Now()
		err, panicked := runRecover(ctx, c.Run)
		if ctx.Err() != nil {
			break
		}
		if err == nil && !panicked {
			s.set(c.Name, func(st *ComponentStatus) { st.State = StateStopped })
			s.Log.Info("component finished", logx.ID("component", c.Name))
			return
		}
		// Neither the error nor the panic value is logged: either can carry content.
		s.Log.Warn("component failed, restarting", logx.ID("component", c.Name))
		s.set(c.Name, func(st *ComponentStatus) { st.State = StateBackoff; st.Restarts++ })
		if time.Since(start) > maxB { // it ran a good while: start the backoff over
			delay = minB
		}
		if !sleepCtx(ctx, jitter(delay)) {
			break
		}
		delay = min(delay*2, maxB)
	}
	s.set(c.Name, func(st *ComponentStatus) { st.State = StateStopped })
}

func runRecover(ctx context.Context, f func(context.Context) error) (err error, panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	return f(ctx), false
}

// jitter returns d scaled by 0.5..1.0 so restarts across devices do not align.
func jitter(d time.Duration) time.Duration { return d/2 + time.Duration(rand.Int64N(int64(d/2)+1)) }

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
