// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/logx"
)

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

func state(s *Supervisor, name string) ComponentStatus {
	for _, c := range s.Status() {
		if c.Name == name {
			return c
		}
	}
	return ComponentStatus{}
}

func TestSupervisorRestartsFailuresAndPanics(t *testing.T) {
	var log bytes.Buffer
	s := &Supervisor{Log: logx.New(&log), MinBackoff: time.Millisecond}
	var runs atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.Run(ctx, Component{Name: "flaky", MaxBackoff: 4 * time.Millisecond, Run: func(ctx context.Context) error {
			switch runs.Add(1) {
			case 1:
				return errors.New("secret-task-content in an error")
			case 2:
				panic("secret-task-content in a panic")
			}
			<-ctx.Done()
			return ctx.Err()
		}})
	}()
	waitFor(t, "third run", func() bool { return runs.Load() >= 3 && state(s, "flaky").State == StateRunning })
	if got := state(s, "flaky").Restarts; got != 2 {
		t.Errorf("restarts = %d, want 2", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if st := state(s, "flaky").State; st != StateStopped {
		t.Errorf("after shutdown: %s", st)
	}
	if strings.Contains(log.String(), "secret-task-content") {
		t.Errorf("error or panic text reached the log: %s", log.String())
	}
	if !strings.Contains(log.String(), "component=flaky") {
		t.Errorf("failure not logged with the component id: %s", log.String())
	}
}

func TestSupervisorFinishedComponentIsNotRestarted(t *testing.T) {
	s := &Supervisor{Log: logx.New(&bytes.Buffer{}), MinBackoff: time.Millisecond}
	var runs atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.Run(ctx, Component{Name: "once", Run: func(context.Context) error { runs.Add(1); return nil }})
	}()
	waitFor(t, "stopped", func() bool { return state(s, "once").State == StateStopped })
	time.Sleep(20 * time.Millisecond)
	if runs.Load() != 1 {
		t.Errorf("ran %d times", runs.Load())
	}
	cancel()
	<-done
}

func TestSupervisorBackoffResetsAfterALongRun(t *testing.T) {
	s := &Supervisor{Log: logx.New(&bytes.Buffer{}), MinBackoff: time.Millisecond}
	var runs atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.Run(ctx, Component{Name: "c", MaxBackoff: 2 * time.Millisecond, Run: func(ctx context.Context) error {
			if runs.Add(1) == 1 {
				time.Sleep(10 * time.Millisecond) // longer than MaxBackoff
			}
			if runs.Load() < 3 {
				return errors.New("x")
			}
			<-ctx.Done()
			return nil
		}})
	}()
	waitFor(t, "third run", func() bool { return runs.Load() >= 3 })
	cancel()
	<-done
}

func TestSupervisorShutdownTimeout(t *testing.T) {
	s := &Supervisor{Log: logx.New(&bytes.Buffer{}), ShutdownTimeout: 20 * time.Millisecond}
	release := make(chan struct{})
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.Run(ctx, Component{Name: "stuck", Run: func(context.Context) error { <-release; return nil }})
	}()
	waitFor(t, "running", func() bool { return state(s, "stuck").State == StateRunning })
	cancel()
	if err := <-done; !errors.Is(err, ErrShutdownTimeout) {
		t.Errorf("got %v", err)
	}
}

func TestSupervisorDefaultsAndSleepCancel(t *testing.T) {
	s := &Supervisor{Log: logx.New(&bytes.Buffer{})} // zero tuning: defaults apply
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.Run(ctx, Component{Name: "fails", Run: func(context.Context) error { return errors.New("x") }})
	}()
	waitFor(t, "backoff", func() bool { return state(s, "fails").State == StateBackoff })
	cancel() // cancels the backoff sleep
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		if d := s.jitter(time.Second); d < 500*time.Millisecond || d > time.Second {
			t.Fatalf("jitter %v out of range", d)
		}
	}
}

func TestSupervisorDefaultBounds(t *testing.T) {
	s := &Supervisor{}
	if s.budget() != 10*time.Second {
		t.Errorf("default shutdown budget %v", s.budget())
	}
	if (&Supervisor{ShutdownTimeout: time.Second}).budget() != time.Second {
		t.Error("a set shutdown budget must be used")
	}
	minB, maxB := s.bounds(Component{})
	if minB != 250*time.Millisecond || maxB != 30*time.Second {
		t.Errorf("default backoff %v..%v", minB, maxB)
	}
	minB, maxB = (&Supervisor{MinBackoff: time.Second}).bounds(Component{MaxBackoff: time.Minute})
	if minB != time.Second || maxB != time.Minute {
		t.Errorf("configured backoff %v..%v", minB, maxB)
	}
}

func TestSupervisorClockAndWaitDefaults(t *testing.T) {
	s := &Supervisor{}
	if d := time.Since(s.clock()); d < 0 || d > time.Minute {
		t.Errorf("clock is not the wall clock: %v", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if !s.pause(ctx, time.Millisecond) {
		t.Error("an uncancelled pause must complete")
	}
	cancel()
	if s.pause(ctx, time.Hour) {
		t.Error("a cancelled pause must stop")
	}
}

// failing runs a component that fails `fails` times, advancing a fake clock by
// `ran` each run, then blocks. It returns the delays the supervisor waited.
func failing(t *testing.T, s *Supervisor, c Component, fails int, ran time.Duration, rnd func(int64) int64) []time.Duration {
	t.Helper()
	var (
		now    time.Time
		delays []time.Duration
		runs   int
	)
	s.now = func() time.Time { return now }
	s.rnd = rnd
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.sleep = func(ctx context.Context, d time.Duration) bool { delays = append(delays, d); return ctx.Err() == nil }
	c.Run = func(ctx context.Context) error {
		runs++
		now = now.Add(ran)
		if runs <= fails {
			return errors.New("x")
		}
		cancel() // the last run ends the test: the supervisor sees the cancelled context
		return nil
	}
	if err := s.Run(ctx, c); err != nil {
		t.Fatal(err)
	}
	return delays
}

func TestSupervisorBackoffDoublesAndIsCapped(t *testing.T) {
	s := &Supervisor{Log: logx.New(&bytes.Buffer{}), MinBackoff: 10 * time.Millisecond}
	low := failing(t, s, Component{Name: "c", MaxBackoff: 50 * time.Millisecond}, 6, time.Millisecond, func(int64) int64 { return 0 })
	want := []time.Duration{5, 10, 20, 25, 25, 25} // half of 10, 20, 40, 50, 50, 50 ms
	for i, w := range want {
		if i >= len(low) || low[i] != w*time.Millisecond {
			t.Fatalf("lowest jitter delays %v, want %v ms", low, want)
		}
	}
	s = &Supervisor{Log: logx.New(&bytes.Buffer{}), MinBackoff: 10 * time.Millisecond}
	high := failing(t, s, Component{Name: "c", MaxBackoff: 50 * time.Millisecond}, 4, time.Millisecond, func(n int64) int64 { return n - 1 })
	want = []time.Duration{10, 20, 40, 50}
	for i, w := range want {
		if i >= len(high) || high[i] != w*time.Millisecond {
			t.Fatalf("highest jitter delays %v, want %v ms", high, want)
		}
	}
	if len(s.Status()) != 1 || s.Status()[0].Restarts != 4 {
		t.Errorf("restarts: %+v", s.Status())
	}
}

func TestSupervisorBackoffRestartsAfterARunLongerThanTheCap(t *testing.T) {
	zero := func(int64) int64 { return 0 }
	// A run of exactly the cap is not "a good while": the delay keeps growing.
	s := &Supervisor{Log: logx.New(&bytes.Buffer{}), MinBackoff: 10 * time.Millisecond}
	got := failing(t, s, Component{Name: "c", MaxBackoff: 80 * time.Millisecond}, 3, 80*time.Millisecond, zero)
	if len(got) < 3 || got[0] != 5*time.Millisecond || got[1] != 10*time.Millisecond || got[2] != 20*time.Millisecond {
		t.Errorf("run of exactly the cap: %v", got)
	}
	// A run longer than the cap starts the backoff over every time.
	s = &Supervisor{Log: logx.New(&bytes.Buffer{}), MinBackoff: 10 * time.Millisecond}
	got = failing(t, s, Component{Name: "c", MaxBackoff: 80 * time.Millisecond}, 3, 81*time.Millisecond, zero)
	if len(got) < 3 || got[0] != 5*time.Millisecond || got[1] != 5*time.Millisecond || got[2] != 5*time.Millisecond {
		t.Errorf("long runs: %v", got)
	}
}

func TestSupervisorStatusBeforeRun(t *testing.T) {
	s := &Supervisor{Log: logx.New(&bytes.Buffer{})}
	if got := s.Status(); len(got) != 0 {
		t.Errorf("before Run: %+v", got)
	}
}

// Constant expressions have no statement for a mutant to be covered by; their
// values are pinned here.
func TestConstantsArePinned(t *testing.T) {
	if defaultMinBackoff != 250*time.Millisecond || defaultMaxBackoff != 30*time.Second || defaultShutdown != 10*time.Second {
		t.Errorf("defaults changed: %v %v %v", defaultMinBackoff, defaultMaxBackoff, defaultShutdown)
	}
}
