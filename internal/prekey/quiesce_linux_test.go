// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package prekey

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// sigBlocked reads the calling thread's blocked-signal mask from /proc.
func sigBlocked(t *testing.T) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		t.Skip("no /proc/thread-self:", err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "SigBlk:"); ok {
			m, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			return m
		}
	}
	t.Fatal("no SigBlk line")
	return 0
}

func TestQuiesceBlocksPreemptionSignal(t *testing.T) {
	restore := quiesce() // locks this goroutine to its thread
	during := sigBlocked(t)
	restore()
	after := sigBlocked(t)
	urg := uint64(1) << (syscall.SIGURG - 1)
	if during&urg == 0 {
		t.Fatalf("SIGURG not blocked inside quiesce: SigBlk=%x", during)
	}
	for _, s := range syncSignals {
		if during&(1<<(s-1)) != 0 {
			t.Fatalf("synchronous signal %d is blocked", s)
		}
	}
	if after&urg != 0 {
		t.Fatalf("SIGURG still blocked after restore: SigBlk=%x", after)
	}
}

// The pool uses it: a callback run by With sees the signal blocked.
func TestWithRunsWithPreemptionSignalBlocked(t *testing.T) {
	f := newFixture(t, nil)
	sp, err := f.pool.Issue(req("c"))
	if err != nil {
		t.Fatal(err)
	}
	var blocked uint64
	if err := f.pool.With(sp.ID, func(*[scalarSize]byte) error { blocked = sigBlocked(t); return nil }); err != nil {
		t.Fatal(err)
	}
	if blocked&(1<<(syscall.SIGURG-1)) == 0 {
		t.Fatalf("SIGURG not blocked in With: SigBlk=%x", blocked)
	}
}

// If the kernel refuses the mask, quiesce still returns a working restore and
// leaves the thread as it was.
func TestQuiesceSurvivesAFailingSigprocmask(t *testing.T) {
	orig := sigprocmask
	t.Cleanup(func() { sigprocmask = orig })
	sigprocmask = func(int, *uint64, *uint64) syscall.Errno { return syscall.EPERM }
	restore := quiesce()
	blocked := sigBlocked(t)
	restore()
	if blocked&(1<<(syscall.SIGURG-1)) != 0 {
		t.Fatalf("SIGURG blocked although sigprocmask failed: %x", blocked)
	}
}

func urgBlocked(m uint64) bool { return m&(1<<(syscall.SIGURG-1)) != 0 }

// Issue is where the scalar is generated and the public key derived: both steps
// must run with the signal blocked, and the mask must be back afterwards.
func TestIssueRunsWithPreemptionSignalBlocked(t *testing.T) {
	f := newFixture(t, nil)
	var inRand, inDerive uint64
	origRand, origDerive := randRead, derivePublic
	t.Cleanup(func() { randRead, derivePublic = origRand, origDerive })
	randRead = func(b []byte) (int, error) {
		if inRand == 0 {
			inRand = sigBlocked(t) | 1<<63 // marker: observed
		}
		return origRand(b)
	}
	derivePublic = func(b []byte) ([]byte, error) { inDerive = sigBlocked(t) | 1<<63; return origDerive(b) }
	if _, err := f.pool.Issue(req("c")); err != nil {
		t.Fatal(err)
	}
	if !urgBlocked(inRand) || !urgBlocked(inDerive) {
		t.Fatalf("SIGURG not blocked in Issue: rand=%x derive=%x", inRand, inDerive)
	}
	if urgBlocked(sigBlocked(t)) {
		t.Fatal("SIGURG still blocked after Issue returned")
	}
}

// Whatever way With ends, the thread gets its signal mask back.
func TestWithRestoresSignalMaskOnErrorAndPanic(t *testing.T) {
	f := newFixture(t, nil)
	sp, err := f.pool.Issue(req("c"))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.pool.With(sp.ID, func(*[scalarSize]byte) error { return errDerivation })
	if urgBlocked(sigBlocked(t)) {
		t.Fatal("SIGURG still blocked after With returned an error")
	}
	func() {
		defer func() { _ = recover() }()
		_ = f.pool.With(sp.ID, func(*[scalarSize]byte) error { panic("boom") })
	}()
	if urgBlocked(sigBlocked(t)) {
		t.Fatal("SIGURG still blocked after With panicked")
	}
}
