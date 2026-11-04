// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/frames"
	"github.com/kalahroudi/parley/internal/outbox"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/receive"
)

// unusable is a prekey the signer really signed whose public key no one can seal to (a low-order point): an
// authenticated peer can hand one out.
func unusable(w *world, signer *dev, caller string, nonce []byte) *prekey.Signed {
	p := prekey.Prekey{Tenant: tenant, DeviceID: signer.id, SigningKeyID: KeyID(signer.sign.Public().(ed25519.PublicKey)), BindingVersion: 1,
		PublicKey: make([]byte, 32), CallerDeviceID: caller, Nonce: nonce, CreatedAt: w.clock().Truncate(time.Second), ExpiresAt: w.clock().Add(10 * time.Minute).Truncate(time.Second)}
	p.ID[0] = 1
	return &prekey.Signed{Prekey: p, Signature: ed25519.Sign(signer.sign, p.Encode())}
}

func TestATargetThatIssuesAnUnusableKeyFailsTheTask(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.onRelay = func(from, to, body string) (bool, string) {
		if strings.Contains(body, "prekey_request") {
			return true, replyBlob(t, body, frames.EncodePrekey(unusable(w, w.devs["bob"], "alice", reqNonce(t, body))))
		}
		return true, ""
	}
	_, st := w.send("alice", "bob", "x")
	if st.State != outbox.Failed || !errors.Is(st.Err, envelope.ErrInvalid) || w.devs["alice"].pool.Outstanding() != 0 || len(w.sent) != 0 {
		t.Fatalf("%+v keys=%d sent=%d", st, w.devs["alice"].pool.Outstanding(), len(w.sent))
	}
}

func TestAPeerThatHandsOutAnUnusableFollowUpKey(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	ch := alice.node.chains[id]
	// bob sends a status whose next-key is signed by bob but cannot be sealed to.
	h := envelope.Header{Tenant: tenant, SenderDevice: "bob", SenderKeyID: KeyID(bob.sign.Public().(ed25519.PublicKey)), BindingVersion: 1, TargetDevice: "alice",
		PrekeyID: receive.PrekeyID(ch.reply.ID), TaskID: id, ContextID: ch.context, Seq: 1, Type: envelope.TypeStatus, IssuedAt: w.clock(), Expiry: w.clock().Add(10 * time.Minute), PrevHash: ch.recvLast}
	m, err := envelope.SealPadded(bob.sign, ch.reply.PublicKey, h, frames.PackInner(unusable(w, bob, "alice", []byte("n")), nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.feed(alice, m.Marshal()); err != nil {
		t.Fatal(err)
	}
	if err := alice.node.Follow(bg, id, envelope.TypeCancel, nil); !errors.Is(err, envelope.ErrInvalid) || alice.node.chains[id].busy {
		t.Fatalf("%v", err)
	}
}

func TestACallerThatHandsOutAnUnusableReplyKey(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	bad := unusable(w, alice, "bob", []byte("n"))
	f := w.forgeTaskWith(alice, bob, bad, func(*prekey.Signed) []byte { return frames.PackInner(bad, []byte("x")) })
	if err := w.feed(bob, f.wire); err != nil {
		t.Fatal(err)
	}
	if err := bob.node.Respond(bg, f.h.TaskID, envelope.TypeStatus, nil); !errors.Is(err, envelope.ErrInvalid) || bob.node.chains[f.h.TaskID].busy {
		t.Fatalf("%v", err)
	}
	if bob.pool.Outstanding() != 0 {
		t.Fatal("the follow-up key made for a reply that could not be sealed was kept")
	}
}

func TestSendTaskEdges(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	a := w.devs["alice"].node
	if err := a.sendTask(bg, outbox.Task{ID: "nope", Target: "bob"}); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	w.devs["alice"].pool.Close() // no key can be made for the reply
	_, st := w.send("alice", "bob", "x")
	if st.State != outbox.Failed || !errors.Is(st.Err, prekey.ErrClosed) {
		t.Fatalf("%+v", st)
	}
}

func TestNewDefaultsDurations(t *testing.T) {
	w := newWorld(t, "alice")
	c := w.devs["alice"].node.cfg
	c.RequestTimeout, c.CancelWait, c.MaxTasks = 0, 0, 0
	n, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if n.cfg.RequestTimeout != DefaultRequestTimeout || n.cfg.CancelWait != DefaultCancelWait || n.cfg.MaxTasks != DefaultMaxTasks {
		t.Fatalf("%+v", n.cfg)
	}
}

// The admit checks and the execute steps, called with states the full path cannot produce (the chain swept or
// replaced between the check and the callback).
func TestChainChecksAndCallbacksAgainstUnexpectedState(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	if _, err := alice.node.cached("ghost"); !errors.Is(err, ErrPeer) {
		t.Fatal(err)
	}
	if err := alice.node.checkNext(nil, "ghost", nil); !errors.Is(err, ErrPeer) {
		t.Fatal(err)
	}
	ch := bob.node.chains[id]
	base := envelope.Header{TaskID: id, SenderDevice: "alice", Seq: ch.recvSeq, PrevHash: ch.recvLast, Type: envelope.TypeCancel}
	wrong := map[string]func(h *envelope.Header){
		"unknown task":  func(h *envelope.Header) { h.TaskID = [16]byte{9} },
		"other sender":  func(h *envelope.Header) { h.SenderDevice = "mallory" },
		"wrong seq":     func(h *envelope.Header) { h.Seq++ },
		"wrong prev":    func(h *envelope.Header) { h.PrevHash = []byte("x") },
		"no key issued": func(h *envelope.Header) {},
	}
	for name, mod := range wrong {
		h := base
		mod(&h)
		if err := bob.node.admitIn(h); !errors.Is(err, ErrState) {
			t.Errorf("admitIn %s: %v", name, err)
		}
	}
	ach := alice.node.chains[id]
	aBase := envelope.Header{TaskID: id, SenderDevice: "bob", Seq: ach.recvSeq, PrevHash: ach.recvLast, Type: envelope.TypeStatus, PrekeyID: receive.PrekeyID(ach.reply.ID)}
	if err := alice.node.admitOut(aBase); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(h *envelope.Header){
		"unknown task": func(h *envelope.Header) { h.TaskID = [16]byte{9} },
		"other sender": func(h *envelope.Header) { h.SenderDevice = "mallory" },
		"wrong seq":    func(h *envelope.Header) { h.Seq++ },
		"wrong prev":   func(h *envelope.Header) { h.PrevHash = []byte("x") },
		"other key":    func(h *envelope.Header) { h.PrekeyID = "00" },
	} {
		h := aBase
		mod(&h)
		if err := alice.node.admitOut(h); !errors.Is(err, ErrState) {
			t.Errorf("admitOut %s: %v", name, err)
		}
	}
	ach.cancel = true
	if err := alice.node.admitOut(aBase); !errors.Is(err, ErrState) {
		t.Errorf("admitOut after cancel: %v", err)
	}
	ach.cancel = false

	// Callbacks for a task that is no longer there.
	pad := func(b []byte) []byte { p, _ := envelope.Pad(b); return p }
	gone := envelope.Header{TaskID: [16]byte{7}, SenderDevice: "alice", Type: envelope.TypeReply, Seq: 1}
	if err := bob.node.executeIn(receive.Delivered{Header: gone, Plaintext: pad(frames.PackInner(nil, nil))}); !errors.Is(err, ErrUnknown) {
		t.Errorf("executeIn: %v", err)
	}
	gone.SenderDevice, gone.Type = "bob", envelope.TypeStatus
	if err := alice.node.executeOut(receive.Delivered{Header: gone, Plaintext: pad(frames.PackInner(nil, nil))}); !errors.Is(err, ErrUnknown) {
		t.Errorf("executeOut: %v", err)
	}
	// A TASK whose id is taken by the time it runs.
	f := w.forgeTask(w.devs["alice"], bob, func(rpk *prekey.Signed) []byte { return frames.PackInner(rpk, nil) }, true)
	if _, err := bob.node.peer(bg, "alice", 0); err != nil {
		t.Fatal(err)
	}
	bob.node.chains[f.h.TaskID] = &chain{role: target}
	if err := bob.node.executeIn(receive.Delivered{Header: f.h, Owner: "o", Plaintext: pad(frames.PackInner(f.rpk, nil))}); !errors.Is(err, ErrBusy) {
		t.Errorf("executeIn duplicate: %v", err)
	}
	delete(bob.node.chains, f.h.TaskID)
}
