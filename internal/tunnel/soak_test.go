// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// T108 (spike 1), client side: 20 forced drops during a 10k-message soak in each
// direction lose or duplicate nothing. The gateway-side half (Device DO, evictions
// that model a deploy) is gateway/test/soak.test.ts.
func TestSoakForcedReconnects(t *testing.T) {
	const total, drops = 10_000, 20
	g := newFakeGateway(t)
	c, _, _ := start(t, g, nil)

	// Daemon to gateway: a steady stream while connections are cut under it.
	go func() {
		for i := 0; i < total; i++ {
			if err := c.Send("m" + strconv.Itoa(i)); err != nil {
				return
			}
			if i%50 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()

	// Gateway to daemon: events 1..total in order; after each drop the gateway
	// re-sends a window of already-delivered events, which the client must drop.
	var (
		mu  sync.Mutex
		got []uint64
	)
	consumed := make(chan struct{})
	go func() {
		for e := range c.Events() {
			mu.Lock()
			got = append(got, e.Seq)
			n := len(got)
			mu.Unlock()
			if n == total {
				close(consumed)
			}
		}
	}()
	pushed := uint64(0)
	push := func(upTo uint64) {
		for ; pushed < upTo; pushed++ {
			g.push(pushed+1, "e"+strconv.FormatUint(pushed+1, 10))
		}
	}
	waitConn := func() {
		waitFor(t, "connection", func() bool { g.mu.Lock(); defer g.mu.Unlock(); return len(g.conns) > 0 })
	}
	for i := 0; i < drops; i++ {
		waitConn()
		push(pushed + total/drops)
		waitFor(t, "events consumed", func() bool {
			// Everything pushed so far has been handed over before the next drop, so a
			// replay below is a true duplicate rather than a missed event.
			mu.Lock()
			defer mu.Unlock()
			return uint64(len(got)) == pushed
		})
		g.drop()
		waitConn()
		for s := uint64(1); s <= pushed && s <= 50; s++ { // replayed window
			g.push(s, "replay")
		}
		time.Sleep(2 * time.Millisecond)
	}
	waitFor(t, "all frames", func() bool { return len(g.received()) == total })
	select {
	case <-consumed:
	case <-time.After(5 * time.Second):
		t.Fatal("not all events delivered")
	}

	for i, b := range g.received() {
		if b != "m"+strconv.Itoa(i) {
			t.Fatalf("frame %d = %q: lost, duplicated or reordered", i, b)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != total {
		t.Fatalf("delivered %d events, want %d", len(got), total)
	}
	for i, s := range got {
		if s != uint64(i+1) {
			t.Fatalf("event %d has seq %d: lost, duplicated or reordered", i, s)
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.hellos) < drops+1 {
		t.Fatalf("only %d connections, want at least %d", len(g.hellos), drops+1)
	}
}
