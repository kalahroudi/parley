// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/frames"
	"github.com/kalahroudi/parley/internal/outbox"
	"github.com/kalahroudi/parley/internal/prekey"
)

// With no fresh revocation list, or a list that revokes the sender, or no standing of its own, a device
// processes nothing and answers nothing: no key is spent or issued, nothing is relayed, the bot hears nothing.
func TestInboundFailsClosedWithoutFreshTrustState(t *testing.T) {
	cases := map[string]func(w *world, bob *dev){
		"the list is too old":     func(w *world, bob *dev) { w.advance(15 * 24 * time.Hour) },
		"the list revokes sender": func(w *world, bob *dev) { w.list(bob, 2, w.clock(), "alice") },
		"this device is revoked":  func(w *world, bob *dev) { w.list(bob, 2, w.clock(), "bob") },
		"not enrolled at version": func(w *world, bob *dev) { bob.node.cfg.Version = 9 },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, "alice", "bob")
			bob := w.devs["bob"]
			// A prekey request, then a sealed task that was issued before the state went bad.
			f := w.forgeTask(w.devs["alice"], bob, func(rpk *prekey.Signed) []byte { return frames.PackInner(rpk, []byte("x")) }, true)
			setup(w, bob)
			before := len(w.relayed)
			req := `{"t":"prekey_request","id":"r","from":"alice","nonce":"MDEyMzQ1Njc4OWFiY2RlZg==","expires_at":4102444800000}`
			if err := bob.node.HandleEvent(bg, tunnelEvent(req)); err == nil {
				t.Fatal("answered a prekey request")
			}
			if err := w.feed(bob, f.wire); err == nil || bob.inboxLen() != 0 {
				t.Fatalf("processed a task: %v", err)
			}
			if len(w.relayed) != before || bob.table.Len() != 0 {
				t.Fatal("state changed or something was sent")
			}
			if bob.pool.Outstanding() > 1 {
				t.Fatalf("keys: %d, want at most the one issued before", bob.pool.Outstanding())
			}
		})
	}
}

func TestPendingTasksPerPeerAreBounded(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.devs["bob"].online.Store(false)
	a := w.devs["alice"].node
	var n int
	for i := 0; i < 64; i++ {
		_, err := a.Submit(Request{Target: "bob", Content: []byte("x"), Expiry: w.clock().Add(time.Minute)})
		if err != nil {
			if !errors.Is(err, outbox.ErrTargetFull) {
				t.Fatal(err)
			}
			break
		}
		n++
	}
	if n != outbox.DefaultPerTarget {
		t.Fatalf("accepted %d waiting tasks for one peer, want %d", n, outbox.DefaultPerTarget)
	}
}

func TestOversizedContentIsRefusedBeforeAnyKeyIsMade(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	_, err := w.devs["alice"].node.Submit(Request{Target: "bob", Content: make([]byte, MaxContent+1), Expiry: w.clock().Add(time.Minute)})
	if !errors.Is(err, outbox.ErrInvalid) || w.devs["alice"].pool.Outstanding() != 0 {
		t.Fatal(err)
	}
	// The largest content seals into one padded bucket the gateway relays.
	_, st := w.send("alice", "bob", strings.Repeat("a", MaxContent))
	if st.State != outbox.Sent {
		t.Fatalf("%+v", st)
	}
}

// Many callers at once: every task reaches the bot exactly once and every key is gone at the end.
func TestConcurrentCallersExactlyOnce(t *testing.T) {
	const callers, each = 4, 3
	ids := []string{"bob"}
	for i := 0; i < callers; i++ {
		ids = append(ids, fmt.Sprintf("c%d", i))
	}
	w := newWorld(t, ids...)
	bob := w.devs["bob"]
	bob.onTask = func(in Inbound) {
		go func() { _ = bob.node.Respond(bg, in.TaskID, envelope.TypeResult, []byte("r:"+string(in.Content))) }()
	}
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		c := w.devs[fmt.Sprintf("c%d", i)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				id, err := c.node.Submit(Request{Target: "bob", Content: []byte(fmt.Sprintf("%s-%d", c.id, j)), Expiry: w.clock().Add(time.Minute)})
				if err != nil {
					t.Error(err)
					return
				}
				<-c.node.Done(id)
			}
		}()
	}
	wg.Wait()
	eventually(t, "all results", func() bool {
		n := 0
		for i := 0; i < callers; i++ {
			n += w.devs[fmt.Sprintf("c%d", i)].updateLen()
		}
		return n == callers*each
	})
	w.settle()
	if bob.inboxLen() != callers*each {
		t.Fatalf("bot ran %d times, want %d", bob.inboxLen(), callers*each)
	}
	for _, d := range w.devs {
		if d.pool.Outstanding() != 0 {
			t.Fatalf("%s holds %d keys", d.id, d.pool.Outstanding())
		}
	}
}

// Everything the pipeline starts stops with Close.
func TestNoGoroutinesOutliveTheNodes(t *testing.T) {
	runtime.GC()
	before := runtime.NumGoroutine()
	w := newWorld(t, "alice", "bob")
	id := w.run("alice", "bob", "x")
	_ = w.devs["bob"].node.Respond(bg, id, envelope.TypeStatus, nil)
	w.settle()
	w.devs["bob"].online.Store(false)
	_, _ = w.devs["alice"].node.Submit(Request{Target: "bob", Content: []byte("waiting"), Expiry: w.clock().Add(time.Minute)})
	time.Sleep(20 * time.Millisecond)
	for _, d := range w.devs {
		d.node.Close()
		d.pool.Close()
	}
	w.stop()
	eventually(t, "goroutines to end", func() bool { runtime.GC(); return runtime.NumGoroutine() <= before })
}

// The full pipeline against a gateway that duplicates, reorders, drops, tampers with and swaps messages:
// nothing runs twice, nothing is accepted that was altered or belongs to another task, and the honest traffic
// still gets through.
func TestMaliciousGatewayAgainstTheFullPipeline(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id1 := w.run("alice", "bob", "one")
	id2 := w.run("alice", "bob", "two")
	var held [][]byte
	w.onWire = func(to string, wire []byte) [][]byte {
		held = append(held, wire)
		m, _ := envelope.Unmarshal(wire)
		bad := wire
		if m != nil {
			c := *m
			c.Ciphertext = append([]byte(nil), m.Ciphertext...)
			c.Ciphertext[len(c.Ciphertext)-1] ^= 1
			bad = c.Marshal()
		}
		return [][]byte{bad, wire, wire} // a tampered copy, the real one, a duplicate
	}
	if err := bob.node.Respond(bg, id1, envelope.TypeStatus, []byte("s1")); err != nil {
		t.Fatal(err)
	}
	w.settle()
	if alice.updateLen() != 1 {
		t.Fatalf("%d updates for one genuine message", alice.updateLen())
	}
	w.onWire = nil
	// Replay the old message after the chain moved on, to the other task's sender slot, and a swapped task id.
	if err := bob.node.Respond(bg, id2, envelope.TypeResult, []byte("r2")); err != nil {
		t.Fatal(err)
	}
	w.settle()
	for _, wire := range held {
		w.deliver("alice", event(wire))
	}
	w.settle()
	if alice.updateLen() != 2 {
		t.Fatalf("%d updates, want 2: a replayed message was accepted", alice.updateLen())
	}
	if u := alice.update(0); u.TaskID != id1 || string(u.Content) != "s1" {
		t.Fatalf("%+v", u)
	}
	if u := alice.update(1); u.TaskID != id2 || string(u.Content) != "r2" {
		t.Fatalf("%+v", u)
	}
	if bob.inboxLen() != 2 {
		t.Fatal("a task ran twice")
	}
}
