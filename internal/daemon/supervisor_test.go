// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

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
	if d := jitter(time.Second); d < 500*time.Millisecond || d > time.Second {
		t.Errorf("jitter %v out of range", d)
	}
}
