// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"errors"
	"sync"
	"testing"
	"time"
)

const testSkew = time.Second

var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newTable(max int) (*Table, *clock) {
	return newCfg(Config{MaxEntries: max})
}

func newCfg(cfg Config) (*Table, *clock) {
	c := &clock{now: t0}
	cfg.Now = c.Now
	if cfg.Skew == 0 {
		cfg.Skew = testSkew
	}
	return New(cfg), c
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
	// Past the expiry but inside the skew the entry is still held.
	c.now = exp.Add(testSkew - time.Nanosecond)
	if tb.Len() != 1 {
		t.Fatal("entry pruned inside the skew window")
	}
	if err := tb.Accept(k, exp); !errors.Is(err, ErrExpired) {
		t.Fatalf("inside skew: %v, want ErrExpired", err)
	}
	c.now = exp.Add(-time.Nanosecond)
	if err := tb.Accept(k, exp); !errors.Is(err, ErrReplay) {
		t.Fatalf("just before expiry: %v, want ErrReplay", err)
	}
	c.now = exp.Add(testSkew)
	if tb.Len() != 0 {
		t.Fatal("entry not pruned at expiry plus skew")
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
		c.now = t0.Add(at*time.Minute + testSkew)
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
	c.now = t0.Add(time.Minute + testSkew)
	if err := tb.Accept(key("d", 3, 0), t0.Add(time.Hour)); err != nil {
		t.Fatalf("after pruning: %v", err)
	}
}

func TestDefaultClock(t *testing.T) {
	tb := New(Config{})
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

func TestBadKeyRefused(t *testing.T) {
	tb, _ := newTable(10)
	exp := t0.Add(time.Minute)
	long := make([]byte, MaxSenderLen+1)
	for i := range long {
		long[i] = 'a'
	}
	for _, sender := range []string{"", string(long)} {
		if err := tb.Accept(Key{Sender: sender}, exp); !errors.Is(err, ErrKey) {
			t.Fatalf("len %d: %v, want ErrKey", len(sender), err)
		}
	}
	if err := tb.Accept(Key{Sender: string(long[:MaxSenderLen])}, exp); err != nil {
		t.Fatalf("max-length sender: %v", err)
	}
}

func TestExpiryBeyondMaxLifetimeRefused(t *testing.T) {
	tb, _ := newCfg(Config{MaxLifetime: time.Hour})
	if err := tb.Accept(key("d", 1, 0), t0.Add(time.Hour+time.Nanosecond)); !errors.Is(err, ErrTooFar) {
		t.Fatalf("got %v, want ErrTooFar", err)
	}
	if tb.Len() != 0 {
		t.Fatal("refused message was recorded")
	}
	if err := tb.Accept(key("d", 1, 0), t0.Add(time.Hour)); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
}

// A flooding sender hits its own quota, and other senders are still served.
func TestSenderQuotaProtectsOthers(t *testing.T) {
	tb, c := newCfg(Config{MaxEntries: 10, MaxPerSender: 2})
	exp := t0.Add(time.Minute)
	for i := range 2 {
		if err := tb.Accept(key("flood", byte(i), 0), exp); err != nil {
			t.Fatal(err)
		}
	}
	if err := tb.Accept(key("flood", 9, 0), exp); !errors.Is(err, ErrQuota) {
		t.Fatalf("got %v, want ErrQuota", err)
	}
	if err := tb.Accept(key("legit", 1, 0), exp); err != nil {
		t.Fatalf("other sender: %v", err)
	}
	// The quota frees as entries expire.
	c.now = exp.Add(testSkew)
	if err := tb.Accept(key("flood", 9, 0), c.now.Add(time.Minute)); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestDefaultsApplied(t *testing.T) {
	tb := New(Config{})
	if tb.cfg.MaxEntries != DefaultMaxEntries || tb.cfg.MaxPerSender != DefaultMaxPerSender ||
		tb.cfg.MaxLifetime != DefaultMaxLifetime || tb.cfg.Skew != DefaultSkew {
		t.Fatalf("defaults not applied: %+v", tb.cfg)
	}
}

// After a flood drains, the heap gives its memory back.
func TestHeapShrinksAfterDrain(t *testing.T) {
	tb, c := newCfg(Config{MaxEntries: 5000, MaxPerSender: 5000})
	exp := t0.Add(time.Minute)
	for i := range 4000 {
		if err := tb.Accept(Key{Sender: "d", Seq: uint64(i)}, exp); err != nil {
			t.Fatal(err)
		}
	}
	c.now = exp.Add(testSkew)
	if tb.Len() != 0 {
		t.Fatal("not drained")
	}
	if cap(tb.byExp) > 1024 {
		t.Fatalf("heap capacity %d held after drain", cap(tb.byExp))
	}
	if len(tb.bySend) != 0 {
		t.Fatal("sender counts leaked")
	}
}

func TestPopShrinkBoundary(t *testing.T) {
	// After one Pop the heap holds n-1 entries; it shrinks only when its
	// capacity is strictly more than 4*(n-1)+shrinkSlack.
	for _, tc := range []struct {
		n, capacity int
		shrinks     bool
	}{
		{10, 4*9 + shrinkSlack, false},
		{10, 4*9 + shrinkSlack + 1, true},
		{1, shrinkSlack + 1, true},
		{1, shrinkSlack, false},
	} {
		h := make(expiryHeap, tc.n, tc.capacity)
		h.Pop()
		if got := cap(h) != tc.capacity; got != tc.shrinks {
			t.Fatalf("n=%d cap=%d: shrank=%v, want %v", tc.n, tc.capacity, got, tc.shrinks)
		}
		if len(h) != tc.n-1 || (tc.shrinks && cap(h) != len(h)) {
			t.Fatalf("n=%d cap=%d: len=%d cap=%d", tc.n, tc.capacity, len(h), cap(h))
		}
	}
}

func TestPopKeepsRemainingEntries(t *testing.T) {
	h := expiryHeap{{key: key("a", 1, 0)}, {key: key("b", 2, 0)}}
	h2 := make(expiryHeap, 2, 1000)
	copy(h2, h)
	h2.Pop()
	if len(h2) != 1 || h2[0].key.Sender != "a" {
		t.Fatalf("remaining = %+v", h2)
	}
}

// Pruning one of a sender's entries must not forget the others in its quota.
func TestQuotaSurvivesPartialPrune(t *testing.T) {
	tb, c := newCfg(Config{MaxEntries: 10, MaxPerSender: 2})
	if err := tb.Accept(key("d", 1, 0), t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := tb.Accept(key("d", 2, 0), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.now = t0.Add(time.Minute + testSkew)
	if err := tb.Accept(key("d", 3, 0), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := tb.Accept(key("d", 4, 0), t0.Add(time.Hour)); !errors.Is(err, ErrQuota) {
		t.Fatalf("got %v, want ErrQuota", err)
	}
}
