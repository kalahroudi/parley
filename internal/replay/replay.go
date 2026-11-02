// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package replay is the daemon's local replay table. It records every accepted
// message by (sender device, task id, sequence) until the message's own signed
// expiry, so a frame the gateway delivers twice, or replays later, is dropped.
// It never relies on the gateway's nonce.
//
// The table is memory only, by design (plan.md): prekeys are memory only too,
// so a restart fails every task in flight and a frame captured before it can no
// longer be opened. It never reaches Accept, so there is nothing for a restart
// to forget. Entries hold ids and timestamps only, never payload or plaintext.
package replay

import (
	"container/heap"
	"errors"
	"sync"
	"time"
)

const (
	// DefaultMaxEntries bounds the table. Entries live at most one task expiry
	// (default 15 min, max 24 h) plus skew, so the bound limits what a flood of
	// valid signed messages can make the daemon hold.
	DefaultMaxEntries = 1 << 20
	// DefaultMaxPerSender stops one sender device filling the table and
	// starving the others.
	DefaultMaxPerSender = DefaultMaxEntries / 16
	// DefaultMaxLifetime is the longest task expiry the protocol allows.
	DefaultMaxLifetime = 24 * time.Hour
	// DefaultSkew is how long an entry outlives its expiry, covering clock skew
	// between the verifier's expiry check and this table's clock.
	DefaultSkew = 5 * time.Minute
	// MaxSenderLen bounds the sender id, so a key has a bounded size.
	MaxSenderLen = 128
)

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
	// ErrQuota means this sender holds its share of the table.
	ErrQuota = errors.New("replay: sender quota exceeded")
	// ErrTooFar means the expiry is beyond the longest lifetime allowed; holding
	// it would let a flood pin entries for longer than any task can live.
	ErrTooFar = errors.New("replay: expiry too far in the future")
	// ErrKey means the sender id is empty or longer than MaxSenderLen.
	ErrKey = errors.New("replay: invalid key")
)

// Key identifies one message.
type Key struct {
	Sender string // sender device id
	Task   [16]byte
	Seq    uint64
}

type entry struct {
	key  Key
	keep time.Time // expiry plus skew: when the entry may be dropped
}

// expiryHeap orders entries by expiry, earliest first.
type expiryHeap []entry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].keep.Before(h[j].keep) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)        { *h = append(*h, x.(entry)) }
func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old) - 1
	e := old[n]
	old[n] = entry{} // drop the sender string reference
	*h = old[:n]
	// Give back the array a flood grew, once the table has drained.
	if cap(*h) > 4*len(*h)+shrinkSlack {
		smaller := make(expiryHeap, len(*h))
		copy(smaller, *h)
		*h = smaller
	}
	return e
}

// shrinkSlack is the spare capacity the heap may keep before Pop reallocates.
const shrinkSlack = 64

// Config sets the table's limits. A zero limit takes its default; Now nil
// means time.Now.
type Config struct {
	MaxEntries   int
	MaxPerSender int
	MaxLifetime  time.Duration
	Skew         time.Duration
	Now          func() time.Time
}

// Table is safe for concurrent use.
type Table struct {
	mu     sync.Mutex
	seen   map[Key]struct{}
	bySend map[string]int
	byExp  expiryHeap
	cfg    Config
}

// New returns an empty table.
func New(cfg Config) *Table {
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	if cfg.MaxPerSender == 0 {
		cfg.MaxPerSender = DefaultMaxPerSender
	}
	if cfg.MaxLifetime == 0 {
		cfg.MaxLifetime = DefaultMaxLifetime
	}
	if cfg.Skew == 0 {
		cfg.Skew = DefaultSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Table{seen: make(map[Key]struct{}), bySend: make(map[string]int), cfg: cfg}
}

// Accept records the message and returns nil the first time it is seen. It
// returns ErrReplay for a repeat, ErrExpired if expiry is not in the future,
// ErrTooFar if expiry is past the longest lifetime, ErrKey for a bad sender id,
// and ErrQuota or ErrFull if there is no room. Call it only after the signature
// verified, so junk frames cannot fill the table. A failed call records
// nothing, and no call ever evicts an entry that is still inside its window.
func (t *Table) Accept(k Key, expiry time.Time) error {
	if k.Sender == "" || len(k.Sender) > MaxSenderLen {
		return ErrKey
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.cfg.Now()
	t.prune(now)
	if !expiry.After(now) {
		return ErrExpired
	}
	if expiry.After(now.Add(t.cfg.MaxLifetime)) {
		return ErrTooFar
	}
	if _, dup := t.seen[k]; dup {
		return ErrReplay
	}
	if t.bySend[k.Sender] >= t.cfg.MaxPerSender {
		return ErrQuota
	}
	if len(t.seen) >= t.cfg.MaxEntries {
		return ErrFull
	}
	t.seen[k] = struct{}{}
	t.bySend[k.Sender]++
	heap.Push(&t.byExp, entry{key: k, keep: expiry.Add(t.cfg.Skew)})
	return nil
}

// Len is the number of entries held.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(t.cfg.Now())
	return len(t.seen)
}

// prune drops entries whose window (expiry plus skew) has passed. Callers hold t.mu.
func (t *Table) prune(now time.Time) {
	for len(t.byExp) > 0 && !t.byExp[0].keep.After(now) {
		e := heap.Pop(&t.byExp).(entry)
		delete(t.seen, e.key)
		if t.bySend[e.key.Sender]--; t.bySend[e.key.Sender] == 0 {
			delete(t.bySend, e.key.Sender)
		}
	}
}
