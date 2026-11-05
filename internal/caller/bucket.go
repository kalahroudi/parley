// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package caller

import (
	"sort"
	"sync"
	"time"
)

// bucket is a token bucket: perMinute tokens at most, refilled evenly over a minute.
type bucket struct {
	mu        sync.Mutex
	perMinute float64
	tokens    float64
	last      time.Time
	now       func() time.Time
}

func newBucket(perMinute int, now func() time.Time) *bucket {
	return &bucket{perMinute: float64(perMinute), tokens: float64(perMinute), last: now(), now: now}
}

func (b *bucket) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.now()
	if d := t.Sub(b.last); d > 0 {
		b.tokens = min(b.perMinute, b.tokens+b.perMinute*d.Seconds()/60)
	}
	b.last = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func sortNewestFirst(ts []*task) {
	sort.Slice(ts, func(i, j int) bool { return ts[i].seq > ts[j].seq })
}
