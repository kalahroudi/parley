// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/frames"
	"github.com/kalahroudi/parley/internal/outbox"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/receive"
)

var bg = context.Background()

// A task goes alice to bob: prekey request, verify, seal, send; bob verifies,
// opens, erases, acknowledges and only then hands it to the bot.
func TestTaskReachesTheBotAfterEraseAndAck(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	bob := w.devs["bob"]
	var outstandingAtHandoff = -1
	bob.onTask = func(Inbound) { outstandingAtHandoff = bob.pool.Outstanding() }
	id := w.run("alice", "bob", "review this diff")

	in := bob.inbox[0]
	if in.Type != envelope.TypeTask || string(in.Content) != "review this diff" || in.TaskID != id || in.Caller != "alice" || in.Owner != "alice@acme.test" {
		t.Fatalf("bot got %+v", in)
	}
	if outstandingAtHandoff != 0 {
		t.Fatalf("the bot was called with %d prekeys still live: erase must come first", outstandingAtHandoff)
	}
	if err := bob.lastErr(); err != nil {
		t.Fatal(err)
	}
	// The wire carried nothing readable.
	for _, m := range w.sent {
		if strings.Contains(string(m.Wire), "review this diff") {
			t.Fatal("plaintext on the wire")
		}
	}
	if st, ok := w.devs["alice"].node.State(id); !ok || st != envelope.TypeTask {
		t.Fatalf("caller state %v %v", st, ok)
	}
}

// The whole conversation: status, a question, the answer, the result. Every
// follow-up key is used once; the reply key lasts until the result.
func TestConversationChain(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "start")
	say := func(typ envelope.Type, text string) {
		t.Helper()
		if err := bob.node.Respond(bg, id, typ, []byte(text)); err != nil {
			t.Fatal(err)
		}
		w.settle()
	}
	say(envelope.TypeStatus, "working")
	say(envelope.TypeInputRequired, "which branch?")
	if got := alice.updateLen(); got != 2 {
		t.Fatalf("%d updates", got)
	}
	if u := alice.update(1); u.Type != envelope.TypeInputRequired || string(u.Content) != "which branch?" || u.TaskID != id {
		t.Fatalf("%+v", u)
	}
	if err := alice.node.Follow(bg, id, envelope.TypeReply, []byte("main")); err != nil {
		t.Fatal(err)
	}
	w.settle()
	if in := bob.inbox[len(bob.inbox)-1]; in.Type != envelope.TypeReply || string(in.Content) != "main" {
		t.Fatalf("%+v", in)
	}
	// The reply was the follow-up key's only use.
	if err := alice.node.Follow(bg, id, envelope.TypeReply, []byte("again")); !errors.Is(err, ErrState) {
		t.Fatalf("second follow-up: %v", err)
	}
	say(envelope.TypeStatus, "still working")
	if bob.pool.Outstanding() != 1 || alice.pool.Outstanding() != 1 {
		t.Fatalf("keys: bob %d alice %d, want the target's follow-up key and the caller's reply key", bob.pool.Outstanding(), alice.pool.Outstanding())
	}
	say(envelope.TypeResult, "done")
	if bob.pool.Outstanding() != 0 || alice.pool.Outstanding() != 0 {
		t.Fatalf("after the result: bob %d alice %d keys live, want none", bob.pool.Outstanding(), alice.pool.Outstanding())
	}
	if st, _ := alice.node.State(id); st != envelope.TypeResult {
		t.Fatalf("state %v", st)
	}
	for i := 0; i < alice.errCount(); i++ {
		if err := alice.errAt(i); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}
	if err := bob.node.Respond(bg, id, envelope.TypeStatus, nil); !errors.Is(err, ErrState) {
		t.Fatalf("a reply after the result: %v", err)
	}
	// A reply after the result is also refused by the caller.
	if err := alice.node.Follow(bg, id, envelope.TypeCancel, nil); !errors.Is(err, ErrState) {
		t.Fatalf("cancel after the result: %v", err)
	}
}

// A target that is offline is waited for; the task goes when it comes back.
func TestOfflineTargetIsWaitedFor(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.devs["bob"].online.Store(false)
	id, err := w.devs["alice"].node.Submit(Request{Target: "bob", Content: []byte("hello"), Expiry: w.clock().Add(15 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "a prekey request to go unanswered", func() bool { w.mu.Lock(); defer w.mu.Unlock(); return len(w.relayed) >= 2 })
	if st, _ := w.devs["alice"].node.Status(id); st.State == outbox.Sent || st.State == outbox.Failed {
		t.Fatalf("status %+v while offline", st)
	}
	if len(w.sent) != 0 {
		t.Fatal("something was sent to an offline target")
	}
	w.devs["bob"].online.Store(true)
	<-w.devs["alice"].node.Done(id)
	w.settle()
	if st, _ := w.devs["alice"].node.Status(id); st.State != outbox.Sent {
		t.Fatalf("status %+v after the target came back", st)
	}
	if w.devs["bob"].inboxLen() != 1 {
		t.Fatal("the task did not arrive")
	}
}

// The target will not issue a prekey (alice is not on its allowlist): the task
// fails, nothing is sent, and alice's reply key is erased.
func TestTargetRefusalFailsTheTaskCleanly(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.devs["bob"].allow["alice@acme.test"] = true // refused
	_, st := w.send("alice", "bob", "x")
	if st.State != outbox.Failed || !errors.Is(st.Err, ErrRefused) {
		t.Fatalf("status %+v", st)
	}
	if len(w.sent) != 0 || w.devs["alice"].pool.Outstanding() != 0 || w.devs["bob"].pool.Outstanding() != 0 {
		t.Fatalf("sent=%d alice keys=%d bob keys=%d", len(w.sent), w.devs["alice"].pool.Outstanding(), w.devs["bob"].pool.Outstanding())
	}
}

// A gateway that answers the prekey request with something the target did not
// sign for this request is refused before anything is sealed.
func TestSubstitutedPrekeyIsRefused(t *testing.T) {
	cases := map[string]func(w *world, body string) string{
		"signed by the gateway's own key": func(w *world, body string) string {
			evil := w.get("evil")
			return replyFrom(t, body, evil.pool, "alice", reqNonce(t, body))
		},
		"another caller's prekey": func(w *world, body string) string {
			return replyFrom(t, body, w.devs["bob"].pool, "carol", reqNonce(t, body))
		},
		"an old nonce": func(w *world, body string) string {
			return replyFrom(t, body, w.devs["bob"].pool, "alice", []byte("another nonce..."))
		},
		"garbage": func(w *world, body string) string { return replyBlob(t, body, []byte("junk")) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, "alice", "bob", "evil")
			w.onRelay = func(from, to, body string) (bool, string) {
				if strings.Contains(body, "prekey_request") {
					return true, mutate(w, body)
				}
				return true, ""
			}
			_, st := w.send("alice", "bob", "x")
			if st.State != outbox.Failed || !errors.Is(st.Err, ErrPrekey) {
				t.Fatalf("status %+v", st)
			}
			if len(w.sent) != 0 || w.devs["alice"].pool.Outstanding() != 0 {
				t.Fatalf("sent=%d alice keys=%d", len(w.sent), w.devs["alice"].pool.Outstanding())
			}
		})
	}
}

func reqNonce(t *testing.T, body string) []byte {
	t.Helper()
	ev, err := frames.ParseEvent(strings.Replace(body, `"to":`, `"from":`, 1))
	if err != nil {
		t.Fatal(err)
	}
	return ev.Relay.Nonce
}

// replyFrom is the answer a pool would give a request, as a relayed event.
func replyFrom(t *testing.T, body string, p *prekey.Pool, caller string, nonce []byte) string {
	t.Helper()
	sp, err := p.Issue(prekey.Request{Caller: caller, Nonce: nonce, TaskExpiry: t0.Add(15 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return replyBlob(t, body, frames.EncodePrekey(sp))
}

func replyBlob(t *testing.T, body string, blob []byte) string {
	t.Helper()
	ev, err := frames.ParseEvent(strings.Replace(body, `"to":`, `"from":`, 1))
	if err != nil {
		t.Fatal(err)
	}
	f, err := frames.ReplyPrekey(ev.Relay.ID, "alice", blob)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Replace(f, `"to":"alice"`, `"from":"bob"`, 1)
}

// No answer in time: the task keeps waiting (nothing was asked of anyone twice
// without an answer, nothing sent) and the reply key is erased each time.
func TestUnansweredPrekeyRequestTimesOut(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.onRelay = func(from, to, body string) (bool, string) { return false, "" } // the gateway swallows everything
	id, err := w.devs["alice"].node.Submit(Request{Target: "bob", Content: []byte("x"), Expiry: w.clock().Add(15 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "two requests", func() bool { w.mu.Lock(); defer w.mu.Unlock(); return len(w.relayed) >= 2 })
	if st, _ := w.devs["alice"].node.Status(id); st.State == outbox.Failed || st.State == outbox.Sent {
		t.Fatalf("status %+v", st)
	}
	if err := w.devs["alice"].node.Abandon(id); err != nil && !errors.Is(err, outbox.ErrSending) {
		t.Fatal(err)
	}
}

// A rate-limited request waits like an offline one.
func TestRateLimitedPrekeyRequestWaits(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	var limited atomic.Bool
	limited.Store(true)
	w.onRelay = func(from, to, body string) (bool, string) {
		if limited.Load() && strings.Contains(body, "prekey_request") {
			limited.Store(false)
			return true, `{"t":"prekey_refused","id":"` + idOf(t, body) + `","from":"bob","reason":"rate_limited","retry_after_ms":5}`
		}
		return true, ""
	}
	w.run("alice", "bob", "x")
}

func idOf(t *testing.T, body string) string {
	t.Helper()
	ev, err := frames.ParseEvent(strings.Replace(body, `"to":`, `"from":`, 1))
	if err != nil {
		t.Fatal(err)
	}
	return ev.Relay.ID
}

// An answer from the wrong device, or to nobody, is dropped.
func TestStrayPrekeyAnswersAreDropped(t *testing.T) {
	w := newWorld(t, "alice", "bob", "carol")
	w.onRelay = func(from, to, body string) (bool, string) {
		if strings.Contains(body, "prekey_request") {
			// carol answers for bob: the node waits for bob, so this is ignored, then bob's own arrives.
			w.deliver("alice", strings.Replace(replyFrom(t, body, w.devs["carol"].pool, "alice", reqNonce(t, body)), `"from":"bob"`, `"from":"carol"`, 1))
			w.deliver("alice", `{"t":"prekey_refused","id":"nobody","from":"bob","reason":"refused"}`)
		}
		return true, ""
	}
	w.run("alice", "bob", "x")
}

// A failing relay means nothing was asked: the task waits.
func TestRelayFailureWaits(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	var fail atomic.Bool
	fail.Store(true)
	w.devs["alice"].node.cfg.Relay = func(body string) error {
		if fail.Swap(false) {
			return errors.New("tunnel down")
		}
		return w.relay("alice", body)
	}
	w.run("alice", "bob", "x")
}

// A gateway that refuses (offline, rate limit) sends nothing to the target; the
// task waits again and the reply key is erased between attempts.
func TestGatewayRefusalOfflineRetries(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	gw := w.gw("alice")
	gw.setFail(&RateLimited{After: time.Millisecond})
	id, err := w.devs["alice"].node.Submit(Request{Target: "bob", Content: []byte("x"), Expiry: w.clock().Add(15 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "a refused send", func() bool { w.mu.Lock(); defer w.mu.Unlock(); return len(w.sent) >= 2 })
	gw.setFail(nil)
	<-w.devs["alice"].node.Done(id)
	w.settle()
	if w.devs["bob"].inboxLen() != 1 || w.devs["alice"].pool.Outstanding() != 1 {
		t.Fatalf("inbox=%d keys=%d", w.devs["bob"].inboxLen(), w.devs["alice"].pool.Outstanding())
	}
}

func TestGatewayHardRefusalFailsTheTask(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.gw("alice").setFail(ErrNotPermitted)
	_, st := w.send("alice", "bob", "x")
	if st.State != outbox.Failed || !errors.Is(st.Err, ErrNotPermitted) || w.devs["alice"].pool.Outstanding() != 0 {
		t.Fatalf("%+v keys=%d", st, w.devs["alice"].pool.Outstanding())
	}
	if _, ok := w.devs["alice"].node.State([16]byte{}); ok {
		t.Fatal("state for an unknown task")
	}
}

// Replies are checked against the chain before their key is spent.
func TestRepliesThatDoNotContinueTheChainBurnNothing(t *testing.T) {
	w := newWorld(t, "alice", "bob", "mallory")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")

	// Hold bob's next two replies instead of delivering them.
	var held [][]byte
	w.onWire = func(to string, wire []byte) [][]byte { held = append(held, wire); return nil }
	for _, s := range []string{"one", "two"} {
		if err := bob.node.Respond(bg, id, envelope.TypeStatus, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	w.onWire = nil
	w.deliver("alice", event(held[1])) // out of order: sequence 2 first
	w.settle()
	if err := alice.lastErr(); !errors.Is(err, receive.ErrRejected) {
		t.Fatalf("out of order: %v", err)
	}
	if alice.pool.Outstanding() != 1 || alice.updateLen() != 0 {
		t.Fatalf("keys=%d updates=%d", alice.pool.Outstanding(), alice.updateLen())
	}
	w.deliver("alice", event(held[0]))
	w.deliver("alice", event(held[1]))
	w.deliver("alice", event(held[0])) // a replay
	w.settle()
	if alice.updateLen() != 2 {
		t.Fatalf("updates=%d, want both in order", alice.updateLen())
	}
	if err := alice.lastErr(); !errors.Is(err, receive.ErrRejected) {
		t.Fatalf("replay: %v", err) // the chain has moved past it
	}
	if alice.pool.Outstanding() != 1 {
		t.Fatal("reply key spent early")
	}
}

// A reply from a device that is not the task's target, however well signed, is
// refused and cannot burn the caller's reply key.
func TestForeignReplyCannotBurnTheReplyKey(t *testing.T) {
	w := newWorld(t, "alice", "bob", "mallory")
	alice, mallory := w.devs["alice"], w.devs["mallory"]
	id := w.run("alice", "bob", "x")
	// mallory learned the reply key (say, from a colluding gateway) and seals to it.
	chain := alice.node.chains[id]
	h := envelope.Header{Tenant: tenant, SenderDevice: "mallory", SenderKeyID: KeyID(mallory.sign.Public().(ed25519Pub)), BindingVersion: 1, TargetDevice: "alice",
		PrekeyID: receive.PrekeyID(chain.reply.ID), TaskID: id, ContextID: chain.context, Seq: 1, Type: envelope.TypeResult, IssuedAt: t0, Expiry: t0.Add(15 * time.Minute), PrevHash: chain.recvLast}
	m, err := envelope.SealPadded(mallory.sign, chain.reply.PublicKey, h, frames.PackInner(nil, []byte("fake result")))
	if err != nil {
		t.Fatal(err)
	}
	w.deliver("alice", event(m.Marshal()))
	w.settle()
	if err := alice.lastErr(); !errors.Is(err, receive.ErrRejected) {
		t.Fatalf("%v", err)
	}
	if alice.pool.Outstanding() != 1 || alice.updateLen() != 0 {
		t.Fatalf("keys=%d updates=%d", alice.pool.Outstanding(), alice.updateLen())
	}
	// bob's real result still arrives.
	if err := w.devs["bob"].node.Respond(bg, id, envelope.TypeResult, []byte("real")); err != nil {
		t.Fatal(err)
	}
	w.settle()
	if alice.updateLen() != 1 || string(alice.update(0).Content) != "real" {
		t.Fatal("the genuine result did not arrive")
	}
}

// Cancel: the follow-up key carries it; the reply key stays for the
// acknowledgment; anything else that arrives meanwhile is refused; a late reply
// after the acknowledgment finds no key.
func TestCancelFlow(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	if err := alice.node.Follow(bg, id, envelope.TypeCancel, nil); !errors.Is(err, ErrNoKey) {
		t.Fatalf("cancel with no follow-up key yet: %v", err)
	}
	if err := bob.node.Respond(bg, id, envelope.TypeStatus, []byte("working")); err != nil {
		t.Fatal(err)
	}
	w.settle()
	if err := bob.node.Respond(bg, id, envelope.TypeCancel, nil); !errors.Is(err, ErrState) {
		t.Fatalf("an acknowledgment before any cancel: %v", err)
	}
	if err := alice.node.Follow(bg, id, envelope.TypeCancel, nil); err != nil {
		t.Fatal(err)
	}
	w.settle()
	if in := bob.inbox[len(bob.inbox)-1]; in.Type != envelope.TypeCancel {
		t.Fatalf("%+v", in)
	}
	if err := bob.node.Respond(bg, id, envelope.TypeStatus, []byte("late")); !errors.Is(err, ErrState) {
		t.Fatalf("a status after a cancel: %v", err)
	}
	if err := alice.node.Follow(bg, id, envelope.TypeCancel, nil); !errors.Is(err, ErrState) {
		t.Fatalf("second cancel: %v", err)
	}
	if err := bob.node.Respond(bg, id, envelope.TypeCancel, nil); err != nil {
		t.Fatal(err)
	}
	w.settle()
	if st, _ := alice.node.State(id); st != envelope.TypeCancel {
		t.Fatalf("state %v", st)
	}
	if alice.pool.Outstanding() != 0 || bob.pool.Outstanding() != 0 {
		t.Fatalf("keys left: alice %d bob %d", alice.pool.Outstanding(), bob.pool.Outstanding())
	}
}

// While a cancel is pending the caller reads only the acknowledgment; if none
// comes, the reply key is erased and the caller is told the task is lost.
func TestUnacknowledgedCancelErasesTheReplyKey(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	_ = bob.node.Respond(bg, id, envelope.TypeStatus, []byte("working"))
	w.settle()
	if err := alice.node.Follow(bg, id, envelope.TypeCancel, nil); err != nil {
		t.Fatal(err)
	}
	w.settle()
	// A status raced the cancel: refused while the cancel is pending.
	var held [][]byte
	w.onWire = func(to string, wire []byte) [][]byte { held = append(held, wire); return nil }
	if err := bob.node.Respond(bg, id, envelope.TypeCancel, nil); err != nil {
		t.Fatal(err)
	}
	w.onWire = nil
	w.advance(31 * time.Second)
	alice.node.Sweep()
	if alice.pool.Outstanding() != 0 {
		t.Fatal("the reply key outlived the cancel wait")
	}
	if u := alice.update(alice.updateLen() - 1); !u.Expired || u.Type != envelope.TypeError {
		t.Fatalf("%+v", u)
	}
	w.deliver("alice", event(held[0])) // the late acknowledgment finds no key
	w.settle()
	if err := alice.lastErr(); err == nil {
		t.Fatal("a reply after the key was erased was accepted")
	}
}

// A task nobody finished fails at its expiry on the caller's side, and the
// target's chain is dropped with its key.
func TestExpiry(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	_ = bob.node.Respond(bg, id, envelope.TypeStatus, []byte("working"))
	w.settle()
	alice.node.Sweep()
	bob.node.Sweep()
	if _, ok := alice.node.State(id); !ok {
		t.Fatal("swept before the expiry")
	}
	w.advance(16 * time.Minute)
	alice.node.Sweep()
	bob.node.Sweep()
	if _, ok := alice.node.State(id); ok {
		t.Fatal("task kept past its expiry")
	}
	if u := alice.update(alice.updateLen() - 1); !u.Expired || u.TaskID != id {
		t.Fatalf("%+v", u)
	}
	if alice.pool.Outstanding() != 0 || bob.pool.Outstanding() != 0 {
		t.Fatalf("keys left: alice %d bob %d", alice.pool.Outstanding(), bob.pool.Outstanding())
	}
}

// Follow-ups and replies the state does not allow.
func TestFollowAndRespondGuards(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	unknown := [16]byte{9}
	if err := alice.node.Follow(bg, unknown, envelope.TypeReply, nil); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	if err := bob.node.Respond(bg, unknown, envelope.TypeStatus, nil); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	if err := bob.node.Follow(bg, id, envelope.TypeCancel, nil); !errors.Is(err, ErrState) {
		t.Fatalf("the target cannot follow up: %v", err)
	}
	if err := alice.node.Respond(bg, id, envelope.TypeStatus, nil); !errors.Is(err, ErrState) {
		t.Fatalf("the caller cannot respond: %v", err)
	}
	if err := bob.node.Respond(bg, id, envelope.TypeTask, nil); !errors.Is(err, ErrState) {
		t.Fatalf("a task is not a response: %v", err)
	}
	if err := alice.node.Follow(bg, id, envelope.TypeStatus, nil); !errors.Is(err, ErrState) {
		t.Fatalf("a status is not a follow-up: %v", err)
	}
	big := make([]byte, MaxContent+1)
	if err := bob.node.Respond(bg, id, envelope.TypeStatus, big); !errors.Is(err, outbox.ErrInvalid) {
		t.Fatal(err)
	}
	if err := alice.node.Follow(bg, id, envelope.TypeReply, big); !errors.Is(err, outbox.ErrInvalid) {
		t.Fatal(err)
	}
	_ = bob.node.Respond(bg, id, envelope.TypeStatus, []byte("w"))
	w.settle()
	// REPLY is for a question.
	if err := alice.node.Follow(bg, id, envelope.TypeReply, []byte("a")); !errors.Is(err, ErrState) {
		t.Fatalf("a reply to no question: %v", err)
	}
}

// Replies to a question nobody asked, and a second question before the answer,
// are refused by the peer's chain checks.
func TestReplyToNoQuestionIsRefusedByTheTarget(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	_ = bob.node.Respond(bg, id, envelope.TypeInputRequired, []byte("q?"))
	w.settle()
	// Force a REPLY that bob never asked for: pretend the question was never asked on his side.
	bob.node.chains[id].asked = false
	if err := alice.node.Follow(bg, id, envelope.TypeReply, []byte("a")); err != nil {
		t.Fatal(err)
	}
	w.settle()
	if err := bob.lastErr(); !errors.Is(err, receive.ErrRejected) {
		t.Fatalf("%v", err)
	}
	if bob.pool.Outstanding() != 1 {
		t.Fatal("the follow-up key was burned by a message that did not belong")
	}
}

// Junk events: unsupported, malformed, and sealed messages from unknown devices.
func TestJunkEventsChangeNothing(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	bob := w.devs["bob"]
	for _, body := range []string{`{}`, `nope`, `{"t":"x"}`, `{"a2a":"1.0","task":{"status":{"message":{"parts":[]}}}}`,
		event([]byte("not an envelope"))} {
		if err := bob.node.HandleEvent(bg, tunnelEvent(body)); err == nil {
			t.Errorf("%q accepted", body)
		}
	}
	if bob.pool.Outstanding() != 0 || bob.inboxLen() != 0 || bob.table.Len() != 0 {
		t.Fatal("junk changed state")
	}
}

// Replaying a delivered TASK frame is dropped: it cannot run twice.
func TestRedeliveredTaskIsDropped(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.run("alice", "bob", "once")
	w.deliver("bob", event(w.sent[0].Wire))
	w.settle()
	if err := w.devs["bob"].lastErr(); err == nil || w.devs["bob"].inboxLen() != 1 {
		t.Fatalf("err=%v inbox=%d", err, w.devs["bob"].inboxLen())
	}
}

// A prekey request is judged by the target: unknown, revoked, denied, pool
// exhausted and a failing relay all end in a refusal or an erased key.
func TestServingPrekeyRequests(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	bob := w.devs["bob"]
	req := func(id string) frames.Relay {
		return frames.Relay{Kind: frames.KindPrekeyRequest, ID: id, Peer: "alice", Nonce: []byte("0123456789abcdef"), TaskExpiry: t0.Add(10 * time.Minute)}
	}
	var out []string
	bob.node.cfg.Relay = func(b string) error { out = append(out, b); return nil }
	if err := bob.node.servePrekey(bg, ptr(req("r1"))); err != nil || len(out) != 1 || !strings.Contains(out[0], `"prekey_reply"`) || bob.pool.Outstanding() != 1 {
		t.Fatalf("%v %v keys=%d", err, out, bob.pool.Outstanding())
	}
	// A stranger.
	r := req("r2")
	r.Peer = "nobody"
	if err := bob.node.servePrekey(bg, &r); !errors.Is(err, ErrPeer) || !strings.Contains(out[1], `"prekey_refused"`) || bob.pool.Outstanding() != 1 {
		t.Fatalf("%v %v", err, out)
	}
	// Not on the allowlist.
	bob.allow["alice@acme.test"] = true
	if err := bob.node.servePrekey(bg, ptr(req("r3"))); !errors.Is(err, ErrPeer) || bob.pool.Outstanding() != 1 {
		t.Fatalf("%v", err)
	}
	bob.allow["alice@acme.test"] = false
	// The per-caller limit.
	for i := 0; ; i++ {
		if err := bob.node.servePrekey(bg, ptr(req("rr"))); err != nil {
			if !errors.Is(err, prekey.ErrRateLimited) || !strings.Contains(out[len(out)-1], `"prekey_refused"`) {
				t.Fatalf("%v", err)
			}
			break
		}
		if i > 20 {
			t.Fatal("no limit")
		}
	}
	// A relay that fails leaves no live key behind.
	held := bob.pool.Outstanding()
	bob.pool.Sweep()
	bob.node.cfg.Relay = func(string) error { return errors.New("down") }
	w.advance(time.Second)
	_ = held
	fresh := newWorld(t, "alice", "bob")
	fb := fresh.devs["bob"]
	fb.node.cfg.Relay = func(string) error { return errors.New("down") }
	if err := fb.node.servePrekey(bg, ptr(req("r9"))); err == nil || fb.pool.Outstanding() != 0 {
		t.Fatalf("%v keys=%d", err, fb.pool.Outstanding())
	}
	// A revoked caller.
	fb.node.cfg.Trust.Guard.IsRevoked("alice")
}

func ptr[T any](v T) *T { return &v }

// A caller whose pool already holds the most reply keys it may for one target
// (replies still outstanding) waits for the target's answers instead of failing
// the task: the ninth task is sent once a result frees a key.
func TestOutstandingReplyKeysLimitWaitsInsteadOfFailing(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	var first [16]byte
	for i := 0; i < prekey.DefaultPerCaller; i++ {
		id := w.run("alice", "bob", fmt.Sprintf("task %d", i))
		if i == 0 {
			first = id
		}
	}
	id, err := alice.node.Submit(Request{Target: "bob", Content: []byte("ninth"), Expiry: w.clock().Add(15 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // many retries at the test's poll interval
	select {
	case <-alice.node.Done(id):
		st, _ := alice.node.Status(id)
		t.Fatalf("the ninth task finished while the limit held: %+v", st)
	default:
	}
	if err := bob.node.Respond(bg, first, envelope.TypeResult, []byte("done")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-alice.node.Done(id):
	case <-time.After(5 * time.Second):
		t.Fatal("the ninth task was never sent after a key was freed")
	}
	w.settle()
	if st, _ := alice.node.Status(id); st.State != outbox.Sent {
		t.Fatalf("status %+v", st)
	}
}

// A bot that panics (here with the message in the panic value) does not take
// the pipeline down: the key was erased and the task acknowledged before the bot
// ran, the error is a fixed one, and the panic value goes nowhere.
func TestPanickingBotCallbackIsContained(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	bob := w.devs["bob"]
	bob.onTask = func(in Inbound) { panic("CANARY-" + string(in.Content)) }
	_, st := w.send("alice", "bob", "hello")
	if st.State != outbox.Sent {
		t.Fatalf("status %+v", st)
	}
	eventually(t, "the task to be handled", func() bool { return bob.errCount() >= 2 })
	var got error
	for i := 0; i < bob.errCount(); i++ {
		if errors.Is(bob.errAt(i), ErrCallback) {
			got = bob.errAt(i)
		}
	}
	if got == nil || strings.Contains(got.Error(), "CANARY") {
		t.Fatalf("error %v", got)
	}
	if n := bob.pool.Outstanding(); n != 0 {
		t.Fatalf("%d keys still held after the panic", n)
	}
	// The pipeline still serves the next task.
	bob.onTask = nil
	w.run("alice", "bob", "again")
}

// A panicking update callback is contained the same way, including from Sweep.
func TestPanickingUpdateCallbackIsContained(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice := w.devs["alice"]
	id := w.run("alice", "bob", "hello")
	alice.node.cfg.OnUpdate = func(Update) { panic("CANARY") }
	w.devs["bob"].node.Respond(bg, id, envelope.TypeResult, []byte("r"))
	w.settle()
	if err := alice.lastErr(); !errors.Is(err, ErrCallback) {
		t.Fatalf("error %v", err)
	}
	id2 := w.run("alice", "bob", "second")
	_ = id2
	w.advance(time.Hour)
	alice.node.Sweep() // must not panic
}

// Follow-up attacks on the target: a device other than the caller that holds
// the issued follow-up key, and the caller sealing to a key of the target's that
// was not the one issued for this follow-up. Both are refused before any key is
// spent, and the genuine follow-up still works.
func TestForeignAndMisdirectedFollowUpsBurnNothing(t *testing.T) {
	w := newWorld(t, "alice", "bob", "mallory")
	alice, bob, mallory := w.devs["alice"], w.devs["bob"], w.devs["mallory"]
	id := w.run("alice", "bob", "x")
	if err := bob.node.Respond(bg, id, envelope.TypeInputRequired, []byte("q?")); err != nil {
		t.Fatal(err)
	}
	w.settle()
	bc := bob.node.chains[id]
	seal := func(sender *dev, key *prekey.Signed, held int) {
		h := envelope.Header{Tenant: tenant, SenderDevice: sender.id, SenderKeyID: KeyID(sender.sign.Public().(ed25519Pub)), BindingVersion: 1, TargetDevice: "bob",
			PrekeyID: receive.PrekeyID(key.ID), TaskID: id, ContextID: bc.context, Seq: 1, Type: envelope.TypeReply, IssuedAt: t0, Expiry: t0.Add(15 * time.Minute), PrevHash: bc.recvLast}
		m, err := envelope.SealPadded(sender.sign, key.PublicKey, h, frames.PackInner(nil, []byte("forged")))
		if err != nil {
			t.Fatal(err)
		}
		w.deliver("bob", event(m.Marshal()))
		w.settle()
		if err := bob.lastErr(); !errors.Is(err, receive.ErrRejected) {
			t.Fatalf("%v", err)
		}
		if bob.pool.Outstanding() != held || bob.inboxLen() != 1 {
			t.Fatalf("keys=%d inbox=%d: a refused follow-up spent a key or ran", bob.pool.Outstanding(), bob.inboxLen())
		}
	}
	seal(mallory, bc.follow, 1) // an enrolled device with the leaked key
	other, err := bob.pool.Issue(prekey.Request{Caller: "alice", Nonce: []byte("another"), TaskExpiry: t0.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	seal(alice, other, 2) // both keys are still held
	_ = bob.pool.Consume(other.ID)
	if err := alice.node.Follow(bg, id, envelope.TypeReply, []byte("answer")); err != nil {
		t.Fatal(err)
	}
	w.settle()
	if bob.inboxLen() != 2 || string(bob.inbox[1].Content) != "answer" {
		t.Fatal("the genuine follow-up did not arrive")
	}
}

// The caller's follow-up can reach the target before the target's own send has
// returned (the gateway already has the question). The chain must expect the
// fresh key by then, or the follow-up is refused and its one-time key is lost.
func TestFollowUpThatOvertakesTheSendReturn(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	w.onWire = func(to string, wire []byte) [][]byte {
		if to != "alice" {
			return [][]byte{wire}
		}
		w.deliver("alice", event(wire))
		w.settle() // alice has read the question
		if err := alice.node.Follow(bg, id, envelope.TypeReply, []byte("answer")); err != nil {
			t.Error(err)
		}
		w.settle() // and bob has handled her answer, while his send is still in progress
		return nil
	}
	if err := bob.node.Respond(bg, id, envelope.TypeInputRequired, []byte("q?")); err != nil {
		t.Fatal(err)
	}
	w.onWire = nil
	if bob.inboxLen() != 2 || string(bob.inbox[1].Content) != "answer" {
		t.Fatalf("inbox %d: the follow-up was lost to the race (%v)", bob.inboxLen(), bob.lastErr())
	}
	if bob.pool.Outstanding() != 0 {
		t.Fatalf("%d keys left", bob.pool.Outstanding())
	}
}
