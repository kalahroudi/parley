// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/frames"
	"github.com/kalahroudi/parley/internal/outbox"
	"github.com/kalahroudi/parley/internal/prekey"
)

// Pinned so a changed limit is a deliberate, reviewed edit (these expressions have no statement for mutation
// testing to cover; see tests/coverage/README.md).
func TestConstantsArePinned(t *testing.T) {
	if MaxContent != 522240 || DefaultMaxTasks != 1024 || DefaultMaxPeers != 1024 || DefaultMaxPending != 256 ||
		DefaultRequestTimeout != 10*time.Second || DefaultCancelWait != 30*time.Second || lookupTimeout != 5*time.Second {
		t.Fatal("a limit changed")
	}
	if a2aTimeout != 30*time.Second || maxReplyBytes != 65536 || tokenSlack != 30*time.Second ||
		errOffline != -32010 || errRateLimited != -32016 || errForbidden != -32013 || errTooLarge != -32014 {
		t.Fatal("a gateway constant changed")
	}
	if caller != 1 || target != 2 {
		t.Fatal("roles")
	}
}

// Every table limit is exact: at the limit one more is refused, one fewer is not.
func TestTableLimitsAreExact(t *testing.T) {
	w := newWorld(t, "alice", "bob", "c1", "c2")
	bob := w.devs["bob"]
	bob.node.cfg.MaxTasks = 2
	good := func(rpk *prekey.Signed) []byte { return frames.PackInner(rpk, []byte("x")) }
	// One task fits under a limit of two, the second fits exactly, the third does not (admit and execute agree).
	for i, from := range []string{"alice", "c1", "c2"} {
		f := w.forgeTask(w.devs[from], bob, good, true)
		err := w.feed(bob, f.wire)
		if (i < 2) != (err == nil) {
			t.Fatalf("task %d: %v", i, err)
		}
	}
	// executeIn alone refuses at the limit too.
	n := len(bob.node.chains)
	bob.node.cfg.MaxTasks = n
	pad := func(b []byte) []byte { p, _ := envelope.Pad(b); return p }
	f := w.forgeTask(w.devs["alice"], bob, good, true)
	f.h.TaskID[0] = 77
	if _, err := bob.node.peer(bg, "alice", 0); err != nil {
		t.Fatal(err)
	}
	if err := bob.node.executeIn(deliveredOf(f.h, pad(frames.PackInner(f.rpk, nil)))); !errors.Is(err, ErrBusy) {
		t.Fatalf("at the limit: %v", err)
	}
	bob.node.cfg.MaxTasks = n + 1
	if err := bob.node.executeIn(deliveredOf(f.h, pad(frames.PackInner(f.rpk, nil)))); err != nil {
		t.Fatalf("under the limit: %v", err)
	}

	// Submit: the queue and the task table.
	a := w.devs["alice"].node
	a.cfg.MaxPending = 1
	w.devs["bob"].online.Store(false)
	exp := w.clock().Add(time.Minute)
	if _, err := a.Submit(Request{Target: "bob", Content: []byte("x"), Expiry: exp}); err != nil {
		t.Fatalf("the first of one: %v", err)
	}
	a.cfg.MaxPending = 10
	a.cfg.MaxTasks = len(a.chains)
	if _, err := a.Submit(Request{Target: "bob", Content: []byte("x"), Expiry: exp}); !errors.Is(err, ErrBusy) {
		t.Fatalf("task table at its limit: %v", err)
	}
	a.cfg.MaxTasks = len(a.chains) + 1
	if _, err := a.Submit(Request{Target: "bob", Content: []byte("y"), Expiry: exp}); err != nil {
		t.Fatalf("task table under its limit: %v", err)
	}
}

func TestContentOfExactlyTheLimitIsAcceptedInFollowUps(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	max := make([]byte, MaxContent)
	if err := bob.node.Respond(bg, id, envelope.TypeInputRequired, max); err != nil {
		t.Fatalf("respond with exactly the limit: %v", err)
	}
	w.settle()
	if err := alice.node.Follow(bg, id, envelope.TypeReply, max); err != nil {
		t.Fatalf("follow with exactly the limit: %v", err)
	}
	w.settle()
	if alice.updateLen() != 1 || bob.inboxLen() != 2 {
		t.Fatal("not delivered")
	}
}

// Two follow-ups in one task: the sequence numbers and previous-message hashes line up each time.
func TestSecondFollowUpContinuesTheChain(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	for _, step := range []func() error{
		func() error { return bob.node.Respond(bg, id, envelope.TypeInputRequired, []byte("q1")) },
		func() error { return alice.node.Follow(bg, id, envelope.TypeReply, []byte("a1")) },
		func() error { return bob.node.Respond(bg, id, envelope.TypeStatus, []byte("s")) },
		func() error { return alice.node.Follow(bg, id, envelope.TypeCancel, nil) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
		w.settle()
		if err := bob.lastErr(); err != nil {
			t.Fatal(err)
		}
	}
	if got := bob.inbox[len(bob.inbox)-1]; got.Type != envelope.TypeCancel {
		t.Fatalf("%+v", got)
	}
}

func TestPeerCacheEvictsOnlyWhenFullAndOnlyOne(t *testing.T) {
	w := newWorld(t, "alice", "bob", "carol", "dave")
	a := w.devs["alice"].node
	a.cfg.MaxPeers = 2
	a.cfg.Directory = func(_ context.Context, d string) (*binding.Signed, error) { return w.devs[d].bind, nil }
	for _, d := range []string{"bob", "carol"} {
		if _, err := a.peer(bg, d, 0); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 12; i++ { // refreshing a held peer never evicts another
		if _, err := a.peer(bg, "bob", 2); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.peers) != 2 || a.peers["carol"] == nil {
		t.Fatalf("a refresh evicted: %d peers", len(a.peers))
	}
	if _, err := a.peer(bg, "dave", 0); err != nil {
		t.Fatal(err)
	}
	if len(a.peers) != 2 || a.peers["dave"] == nil {
		t.Fatalf("a new peer into a full cache must evict exactly one: %d", len(a.peers))
	}
}

func TestSweepIsExactAboutWhatItEnds(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	short := make([][16]byte, 0)
	long := make([][16]byte, 0)
	for i := 0; i < 4; i++ {
		for _, d := range []time.Duration{time.Minute, 10 * time.Minute} {
			id, err := alice.node.Submit(Request{Target: "bob", Content: []byte(fmt.Sprint(i)), Expiry: w.clock().Add(d)})
			if err != nil {
				t.Fatal(err)
			}
			<-alice.node.Done(id)
			if d == time.Minute {
				short = append(short, id)
			} else {
				long = append(long, id)
			}
		}
	}
	w.settle()
	w.advance(2 * time.Minute)
	alice.node.Sweep()
	bob.node.Sweep()
	for _, id := range short {
		if _, ok := alice.node.State(id); ok {
			t.Fatal("an expired task was kept")
		}
	}
	for _, id := range long {
		if _, ok := alice.node.State(id); !ok {
			t.Fatal("a live task was dropped")
		}
	}
	if alice.updateLen() != len(short) || bob.updateLen() != 0 {
		t.Fatalf("expiry updates: alice %d (want %d), bob %d (want none: a target tells nobody)", alice.updateLen(), len(short), bob.updateLen())
	}
	// A finished task is not reported as lost when its time runs out.
	w.advance(20 * time.Minute)
	alice.node.Sweep()
	if alice.updateLen() != len(short)+len(long) {
		t.Fatalf("updates %d", alice.updateLen())
	}
}

func TestCancelWaitOnlyEndsTheCallersUnacknowledgedCancel(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	_ = bob.node.Respond(bg, id, envelope.TypeStatus, nil)
	w.settle()
	if err := alice.node.Follow(bg, id, envelope.TypeCancel, nil); err != nil {
		t.Fatal(err)
	}
	w.settle()
	// Before the wait is over nothing is erased or reported.
	w.advance(10 * time.Second)
	alice.node.Sweep()
	bob.node.Sweep()
	if alice.pool.Outstanding() != 1 || alice.updateLen() != 1 || bob.node.chains[id].done {
		t.Fatalf("early sweep: keys=%d updates=%d", alice.pool.Outstanding(), alice.updateLen())
	}
	// After it, the target's own chain (which also has cancel set) is untouched; only the caller's is ended.
	w.advance(30 * time.Second)
	bob.node.Sweep()
	if bob.node.chains[id].done {
		t.Fatal("the target's chain was ended by the caller's cancel wait")
	}
	if err := bob.node.Respond(bg, id, envelope.TypeCancel, nil); err != nil {
		t.Fatal(err)
	}
	w.settle()
	n := alice.updateLen()
	alice.node.Sweep() // acknowledged: done, so not reported lost
	if alice.updateLen() != n {
		t.Fatal("an acknowledged cancel was reported lost")
	}
}

// Follow loses to a chain that vanished, or finished, while it was sealing.
func TestFollowRechecksTheChainBeforeSending(t *testing.T) {
	for name, mutate := range map[string]func(a *Node, id [16]byte){
		"the task is gone":      func(a *Node, id [16]byte) { a.mu.Lock(); delete(a.chains, id); a.mu.Unlock() },
		"the task has finished": func(a *Node, id [16]byte) { a.mu.Lock(); a.chains[id].done = true; a.mu.Unlock() },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, "alice", "bob")
			alice, bob := w.devs["alice"], w.devs["bob"]
			id := w.run("alice", "bob", "x")
			_ = bob.node.Respond(bg, id, envelope.TypeStatus, nil)
			w.settle()
			a := alice.node
			a.mu.Lock()
			clear(a.peers)
			a.mu.Unlock()
			sent := len(w.sent)
			a.cfg.Directory = func(_ context.Context, d string) (*binding.Signed, error) {
				mutate(a, id)
				return w.devs[d].bind, nil
			}
			if err := a.Follow(bg, id, envelope.TypeCancel, nil); !errors.Is(err, ErrState) || len(w.sent) != sent {
				t.Fatalf("%v sent=%d", err, len(w.sent)-sent)
			}
		})
	}
}

func TestFollowUpsSetOnlyTheirOwnState(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	_ = bob.node.Respond(bg, id, envelope.TypeInputRequired, []byte("q"))
	w.settle()
	if c := alice.node.chains[id]; !c.input || c.cancel {
		t.Fatal("setup")
	}
	if err := alice.node.Follow(bg, id, envelope.TypeReply, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if c := alice.node.chains[id]; c.input || c.cancel {
		t.Fatalf("a reply must clear the question and not cancel: input=%v cancel=%v", c.input, c.cancel)
	}
	w.settle()
	_ = bob.node.Respond(bg, id, envelope.TypeInputRequired, []byte("q2"))
	w.settle()
	if err := alice.node.Follow(bg, id, envelope.TypeCancel, nil); err != nil {
		t.Fatal(err)
	}
	c := alice.node.chains[id]
	if !c.cancel || !c.input || !c.cancelBy.After(w.clock()) {
		t.Fatalf("a cancel sets cancel and its deadline and leaves the question: %+v", c)
	}
}

var _ = outbox.ErrFull

type spyGW struct {
	Gateway
	sends, cancels []string
}

func (s *spyGW) Send(ctx context.Context, m Outgoing) error {
	s.sends = append(s.sends, m.Kind)
	return s.Gateway.Send(ctx, m)
}

func (s *spyGW) Cancel(ctx context.Context, m Outgoing) error {
	s.cancels = append(s.cancels, m.Kind)
	return s.Gateway.Cancel(ctx, m)
}

// A cancel goes out as CancelTask and everything else as SendMessage: the gateway refuses the other way round.
func TestCancelUsesCancelTaskAndReplyUsesSendMessage(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	spy := &spyGW{Gateway: alice.node.cfg.Gateway}
	alice.node.cfg.Gateway = spy
	_ = bob.node.Respond(bg, id, envelope.TypeInputRequired, []byte("q"))
	w.settle()
	if err := alice.node.Follow(bg, id, envelope.TypeReply, []byte("a")); err != nil {
		t.Fatal(err)
	}
	w.settle()
	_ = bob.node.Respond(bg, id, envelope.TypeStatus, nil)
	w.settle()
	if err := alice.node.Follow(bg, id, envelope.TypeCancel, nil); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(spy.sends) != "[REPLY]" || fmt.Sprint(spy.cancels) != "[CANCEL]" {
		t.Fatalf("sends %v cancels %v", spy.sends, spy.cancels)
	}
}
