// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package botproc

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestLaunchRegistersWhileHoldingTheRegistry(t *testing.T) {
	var r Registry
	release := make(chan struct{})
	started := make(chan struct{})
	launched := make(chan func())
	go func() {
		remove, err := r.Launch(func() (int, error) { close(started); <-release; return os.Getpid(), nil })
		if err != nil {
			t.Error(err)
		}
		launched <- remove
	}()
	<-started
	answered := make(chan struct{})
	go func() { r.Owns(os.Getpid()); close(answered) }()
	select {
	case <-answered:
		t.Fatal("a question was answered while a bot was still being started")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	remove := <-launched
	<-answered
	remove()
}

func TestLaunchStartFailureRegistersNothing(t *testing.T) {
	var r Registry
	boom := errors.New("cannot start")
	if remove, err := r.Launch(func() (int, error) { return 0, boom }); !errors.Is(err, boom) || remove != nil {
		t.Fatalf("%v, remove func present: %v", err, remove != nil)
	}
	if len(r.pids) != 0 {
		t.Errorf("registered after a failed start: %v", r.pids)
	}
}

func TestRemoveForgetsTheBotOnceAndOnlyOnce(t *testing.T) {
	var r Registry
	first, _ := r.Launch(func() (int, error) { return 7, nil })
	second, _ := r.Launch(func() (int, error) { return 7, nil })
	first()
	first() // a second call must not remove the other registration
	if r.pids[7] != 1 {
		t.Fatalf("registrations of 7: %d, want 1", r.pids[7])
	}
	second()
	if _, ok := r.pids[7]; ok || len(r.pids) != 0 {
		t.Errorf("still registered: %v", r.pids)
	}
}

func TestRemoveIsSafeFromManyGoroutines(t *testing.T) {
	var r Registry
	remove, _ := r.Launch(func() (int, error) { return 9, nil })
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); remove() }()
	}
	wg.Wait()
	if len(r.pids) != 0 {
		t.Errorf("%v", r.pids)
	}
}

// With no bot running, a live caller is not a bot, and a caller that is gone cannot be judged.
func TestOwnsWithNoBotRunning(t *testing.T) {
	var r Registry
	if own, err := r.Owns(os.Getpid()); own || err != nil {
		t.Errorf("this process: %v %v", own, err)
	}
	if _, err := r.Owns(deadPID(t)); !errors.Is(err, ErrUnknown) {
		t.Errorf("a process that has gone: %v", err)
	}
}
