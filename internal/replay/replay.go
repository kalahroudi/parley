// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package replay is the daemon's local replay table. It records every accepted
// message by (sender device, task id, sequence) until the message's own signed
// expiry, so a frame the gateway delivers twice, or replays later, is dropped.
// It never relies on the gateway's nonce.
//
// The table is memory only: prekeys are memory only too, so a restart fails
// every task in flight and nothing recorded here could be replayed against a
// key that survives it.
package replay

import (
	"container/heap"
	"errors"
	"sync"
	"time"
)

// DefaultMaxEntries bounds the table. Entries live at most one task expiry
// (default 15 min, max 24 h), so the bound limits what a flood of valid
// signed messages can make the daemon hold.
const DefaultMaxEntries = 1 << 20

var (
	// ErrReplay means this (sender, task, sequence) was already accepted.
	ErrReplay = errors.New("replay: message already accepted")
	// ErrExpired means the message is past its signed expiry; it is refused
	// rather than recorded, because the entry would be pruned at once and the
	// message could then be replayed.
	ErrExpired = errors.New("replay: message expired")
	// ErrFull means the table is at capacity with unexpired entries. It fails
	// closed: evicting one would let that message be replayed.
	ErrFull = errors.New("replay: table full")
)

// Key identifies one message.
type Key struct {
	Sender string // sender device id
	Task   [16]byte
	Seq    uint64
}

type entry struct {
	key    Key
	expiry time.Time
}

// expiryHeap orders entries by expiry, earliest first.
type expiryHeap []entry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].expiry.Before(h[j].expiry) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)        { *h = append(*h, x.(entry)) }
func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old) - 1
	e := old[n]
	*h = old[:n]
	return e
}

// Table is safe for concurrent use.
type Table struct {
	mu    sync.Mutex
	seen  map[Key]struct{}
	byExp expiryHeap
	max   int
	now   func() time.Time
}

// New returns an empty table holding at most max unexpired entries. now is the
// clock; nil means time.Now.
func New(max int, now func() time.Time) *Table {
	if now == nil {
		now = time.Now
	}
	return &Table{seen: make(map[Key]struct{}), max: max, now: now}
}

// Accept records the message and returns nil the first time it is seen. It
// returns ErrReplay for a repeat, ErrExpired if expiry is not in the future,
// and ErrFull if the table has no room. Call it only after the signature
// verified, so junk frames cannot fill the table. A failed call records nothing.
func (t *Table) Accept(k Key, expiry time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.prune(now)
	if !expiry.After(now) {
		return ErrExpired
	}
	if _, dup := t.seen[k]; dup {
		return ErrReplay
	}
	if len(t.seen) >= t.max {
		return ErrFull
	}
	t.seen[k] = struct{}{}
	heap.Push(&t.byExp, entry{key: k, expiry: expiry})
	return nil
}

// Len is the number of unexpired entries held.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(t.now())
	return len(t.seen)
}

// prune drops entries whose expiry has passed. Callers hold t.mu.
func (t *Table) prune(now time.Time) {
	for len(t.byExp) > 0 && !t.byExp[0].expiry.After(now) {
		e := heap.Pop(&t.byExp).(entry)
		delete(t.seen, e.key)
	}
}
