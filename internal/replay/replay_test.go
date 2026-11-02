// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"errors"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newTable(max int) (*Table, *clock) {
	c := &clock{now: t0}
	return New(max, c.Now), c
}

func key(sender string, task byte, seq uint64) Key {
	return Key{Sender: sender, Task: [16]byte{0: task}, Seq: seq}
}

func TestAcceptThenReplay(t *testing.T) {
	tb, _ := newTable(10)
	k := key("dev-a", 1, 0)
	exp := t0.Add(15 * time.Minute)
	if err := tb.Accept(k, exp); err != nil {
		t.Fatal(err)
	}
	if err := tb.Accept(k, exp); !errors.Is(err, ErrReplay) {
		t.Fatalf("second accept = %v, want ErrReplay", err)
	}
}

func TestKeyComponentsAreDistinct(t *testing.T) {
	tb, _ := newTable(10)
	exp := t0.Add(time.Minute)
	for _, k := range []Key{key("dev-a", 1, 0), key("dev-b", 1, 0), key("dev-a", 2, 0), key("dev-a", 1, 1)} {
		if err := tb.Accept(k, exp); err != nil {
			t.Fatalf("%+v: %v", k, err)
		}
	}
	if tb.Len() != 4 {
		t.Fatalf("Len = %d, want 4", tb.Len())
	}
}

func TestExpiredIsRefusedAndNotRecorded(t *testing.T) {
	tb, _ := newTable(10)
	for _, exp := range []time.Time{t0, t0.Add(-time.Second)} {
		if err := tb.Accept(key("d", 1, 0), exp); !errors.Is(err, ErrExpired) {
			t.Fatalf("expiry %v: %v, want ErrExpired", exp, err)
		}
	}
	if tb.Len() != 0 {
		t.Fatal("expired message was recorded")
	}
}

func TestPrunedAtExpiry(t *testing.T) {
	tb, c := newTable(10)
	k := key("d", 1, 0)
	exp := t0.Add(time.Minute)
	if err := tb.Accept(k, exp); err != nil {
		t.Fatal(err)
	}
	c.now = exp.Add(-time.Nanosecond)
	if err := tb.Accept(k, exp); !errors.Is(err, ErrReplay) {
		t.Fatalf("just before expiry: %v, want ErrReplay", err)
	}
	c.now = exp
	if tb.Len() != 0 {
		t.Fatal("entry not pruned at expiry")
	}
	// The same message is now expired, so it still cannot be accepted again.
	if err := tb.Accept(k, exp); !errors.Is(err, ErrExpired) {
		t.Fatalf("after expiry: %v, want ErrExpired", err)
	}
}

func TestPruneOrdersByExpiry(t *testing.T) {
	tb, c := newTable(10)
	// Inserted out of order: the heap must still release the earliest first.
	for i, d := range []time.Duration{3, 1, 2} {
		if err := tb.Accept(key("d", byte(i), 0), t0.Add(d*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	for want, at := range []time.Duration{0, 1, 2, 3} {
		c.now = t0.Add(at * time.Minute)
		if got := tb.Len(); got != 3-want {
			t.Fatalf("at +%dm: Len = %d, want %d", at, got, 3-want)
		}
	}
}

func TestFullFailsClosedUntilSpaceFrees(t *testing.T) {
	tb, c := newTable(2)
	if err := tb.Accept(key("d", 1, 0), t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := tb.Accept(key("d", 2, 0), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := tb.Accept(key("d", 3, 0), t0.Add(time.Hour)); !errors.Is(err, ErrFull) {
		t.Fatalf("got %v, want ErrFull", err)
	}
	// A replay of a held entry is reported as a replay, not as full.
	if err := tb.Accept(key("d", 2, 0), t0.Add(time.Hour)); !errors.Is(err, ErrReplay) {
		t.Fatalf("got %v, want ErrReplay", err)
	}
	// Nothing was evicted to make room: the held entries are still refused.
	if err := tb.Accept(key("d", 1, 0), t0.Add(time.Minute)); !errors.Is(err, ErrReplay) {
		t.Fatalf("got %v, want ErrReplay", err)
	}
	c.now = t0.Add(time.Minute)
	if err := tb.Accept(key("d", 3, 0), t0.Add(time.Hour)); err != nil {
		t.Fatalf("after pruning: %v", err)
	}
}

func TestDefaultClock(t *testing.T) {
	tb := New(DefaultMaxEntries, nil)
	if err := tb.Accept(key("d", 1, 0), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := tb.Accept(key("d", 1, 0), time.Now().Add(time.Hour)); !errors.Is(err, ErrReplay) {
		t.Fatalf("got %v, want ErrReplay", err)
	}
}

// Many goroutines race to accept one message: exactly one may win.
func TestConcurrentAcceptOnce(t *testing.T) {
	tb, _ := newTable(10)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tb.Accept(key("d", 1, 0), t0.Add(time.Hour)) == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d goroutines accepted the same message, want 1", wins)
	}
}
