// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// T206: each attack a malicious gateway can mount, run against the harness in
// malgw_test.go. Every test first shows the honest path works in the same
// setup, so a rejection is the defence and not a broken harness.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/replay"
)

func one(t *testing.T, errs []error) error {
	t.Helper()
	if len(errs) != 1 {
		t.Fatalf("want one delivery verdict, got %d: %v", len(errs), errs)
	}
	return errs[0]
}

func wantOK(t *testing.T, errs []error) {
	t.Helper()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("honest delivery refused: %v", err)
		}
	}
}

func wantErr(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// start sends a task from alice to bob and has bob answer with a status, so
// both sides hold follow-up keys.
func start(t *testing.T, w *world) [16]byte {
	t.Helper()
	id, errs, err := w.dev("alice").sendTask("bob", []byte("review this"))
	if err != nil {
		t.Fatal(err)
	}
	wantOK(t, errs)
	wantOK(t, w.dev("bob").reply(id, envelope.TypeStatus, []byte("working")))
	return id
}

func TestHonestGateway(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.dev("alice"), w.dev("bob")
	id := start(t, w)
	if got := string(bob.in[id].content); got != "review this" || bob.ran != 1 {
		t.Fatalf("bob got %q, ran %d", got, bob.ran)
	}
	if bob.pool.Outstanding() != 0 {
		t.Fatal("the prekey was not erased after use")
	}
	wantOK(t, bob.reply(id, envelope.TypeResult, []byte("looks fine")))
	o := alice.out[id]
	if o.state != envelope.TypeResult || string(o.results[1]) != "looks fine" || o.rsk != nil {
		t.Fatalf("state %v, results %q, key erased %v", o.state, o.results, o.rsk == nil)
	}

	// An honest cancel is acknowledged and then the reply key goes.
	id = start(t, w)
	errs, err := alice.cancel(id)
	if err != nil {
		t.Fatal(err)
	}
	wantOK(t, errs)
	if !bob.in[id].canceled {
		t.Fatal("bob did not see the cancel")
	}
	wantOK(t, bob.reply(id, envelope.TypeCancel, nil))
	if err := alice.finishCancel(id); err != nil || alice.out[id].rsk != nil {
		t.Fatalf("finishCancel: %v", err)
	}
}

func TestKeySubstitution(t *testing.T) {
	t.Run("a binding signed by the gateway, not the root", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		other, _ := newRootOf(t)
		w.gw.onBinding = func(id string, honest *binding.Signed) *binding.Signed {
			b, err := binding.Sign(other, binding.Binding{Tenant: tenant, Owner: "bob@acme.test", DeviceID: id,
				SigningKey: pub, Version: 9, NotAfter: w.now.Add(binding.Lifetime)})
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		wantErr(t, w.dev("alice").learn("bob"), binding.ErrBadSignature)
	})
	t.Run("a genuine binding for another device under the target's name", func(t *testing.T) {
		w := newWorld(t, "alice", "bob", "carol")
		w.gw.onBinding = func(string, *binding.Signed) *binding.Signed { return w.gw.bind["carol"] }
		wantErr(t, w.dev("alice").learn("bob"), errWrongDevice)
	})
	t.Run("an old genuine binding served after a re-approval", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		old := w.gw.bind["bob"]
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		w.gw.bind["bob"] = w.approve("bob", pub, 2)
		if err := w.dev("alice").learn("bob"); err != nil {
			t.Fatal(err)
		}
		w.gw.onBinding = func(string, *binding.Signed) *binding.Signed { return old }
		wantErr(t, w.dev("alice").learn("bob"), binding.ErrRollback)
	})
	t.Run("a prekey for the gateway's own key", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		_, evilPriv, _ := ed25519.GenerateKey(rand.Reader)
		evil := newKey(t)
		w.gw.onPrekey = func(from, to string, honest *prekey.Signed) (*prekey.Signed, error) {
			forged := *honest
			forged.PublicKey = evil.PublicKey().Bytes()
			forged.Signature = ed25519.Sign(evilPriv, forged.Encode())
			return &forged, nil
		}
		_, _, err := w.dev("alice").sendTask("bob", []byte("secret"))
		wantErr(t, err, prekey.ErrBadSig)
		if w.gw.sent != 0 {
			t.Fatal("alice sent a task to a key she could not verify")
		}
	})
	t.Run("a genuine prekey with its public key swapped", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		evil := newKey(t)
		w.gw.onPrekey = func(from, to string, honest *prekey.Signed) (*prekey.Signed, error) {
			swapped := *honest
			swapped.PublicKey = evil.PublicKey().Bytes()
			return &swapped, nil
		}
		_, _, err := w.dev("alice").sendTask("bob", []byte("secret"))
		wantErr(t, err, prekey.ErrBadSig)
	})
	t.Run("a task forged in alice's name to bob's real prekey", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		bob := w.dev("bob")
		// The gateway asks bob for a prekey on alice's behalf, then seals its
		// own task and signs it with a key of its own.
		s, err := bob.issue("alice", []byte("n"), w.now.Add(taskTTL))
		if err != nil {
			t.Fatal(err)
		}
		_, evilPriv, _ := ed25519.GenerateKey(rand.Reader)
		forger := *w.dev("alice") // a copy: only its signing key differs
		forger.sign = evilPriv
		_, wire := forger.sealTask("bob", s, []byte("do evil"))
		wantErr(t, one(t, w.gw.push("bob", wire)), envelope.ErrBadSignature)
		if bob.ran != 0 || bob.pool.Outstanding() != 1 {
			t.Fatalf("ran %d, outstanding %d: a forged frame must run nothing and burn nothing", bob.ran, bob.pool.Outstanding())
		}
	})
	t.Run("a task whose prekey object is not bob's", func(t *testing.T) {
		w := newWorld(t, "alice", "bob", "carol")
		bob := w.dev("bob")
		s, err := bob.issue("alice", []byte("n"), w.now.Add(taskTTL))
		if err != nil {
			t.Fatal(err)
		}
		// alice (or someone with her key) embeds carol's signature on bob's id.
		forged := *s
		forged.Signature = ed25519.Sign(w.dev("carol").sign, s.Encode())
		_, wire := w.dev("alice").sealTask("bob", &forged, []byte("x"))
		wantErr(t, one(t, w.gw.push("bob", wire)), errBadPrekeyBlob)
	})
}

func newRootOf(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestReplay(t *testing.T) {
	t.Run("a task delivered twice runs once", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		bob := w.dev("bob")
		id, errs, err := w.dev("alice").sendTask("bob", []byte("pay"))
		if err != nil {
			t.Fatal(err)
		}
		wantOK(t, errs)
		wire := w.gw.seen["bob"][0]
		_ = id
		wantErr(t, one(t, w.gw.push("bob", wire)), prekey.ErrConsumed)
		if bob.ran != 1 {
			t.Fatalf("task ran %d times", bob.ran)
		}
	})
	t.Run("the same frame duplicated by the gateway in one hop", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		w.gw.onMsg = func(_ string, wire []byte) [][]byte { return [][]byte{wire, wire, wire} }
		_, errs, err := w.dev("alice").sendTask("bob", []byte("pay"))
		if err != nil {
			t.Fatal(err)
		}
		if errs[0] != nil {
			t.Fatal(errs[0])
		}
		wantErr(t, errs[1], prekey.ErrConsumed)
		wantErr(t, errs[2], prekey.ErrConsumed)
		if w.dev("bob").ran != 1 {
			t.Fatal("duplicated task ran more than once")
		}
	})
	t.Run("a reply delivered again is caught by the replay table", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		id := start(t, w)
		status := w.gw.seen["alice"][0]
		wantErr(t, one(t, w.gw.push("alice", status)), replay.ErrReplay)
		if n := len(w.dev("alice").out[id].results); n != 1 {
			t.Fatalf("alice recorded %d results", n)
		}
	})
	t.Run("a task replayed after its expiry", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		_, errs, err := w.dev("alice").sendTask("bob", []byte("pay"))
		if err != nil {
			t.Fatal(err)
		}
		wantOK(t, errs)
		w.now = w.now.Add(taskTTL + time.Minute)
		wantErr(t, one(t, w.gw.push("bob", w.gw.seen["bob"][0])), errExpired)
	})
	t.Run("a cancel replayed", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		id := start(t, w)
		errs, err := w.dev("alice").cancel(id)
		if err != nil {
			t.Fatal(err)
		}
		wantOK(t, errs)
		wantErr(t, one(t, w.gw.push("bob", w.gw.seen["bob"][1])), errNoKey)
	})
	t.Run("alice's own task reflected back to her", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		_, errs, _ := w.dev("alice").sendTask("bob", []byte("x"))
		wantOK(t, errs)
		wantErr(t, one(t, w.gw.push("alice", w.gw.seen["bob"][0])), errUnknownSender)
	})
	t.Run("bob's reply reflected back to bob", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		start(t, w)
		wantErr(t, one(t, w.gw.push("bob", w.gw.seen["alice"][0])), errUnknownSender)
	})
}

func TestReorder(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.dev("alice"), w.dev("bob")
	id := start(t, w)
	r2 := bob.replyWire(id, envelope.TypeStatus, []byte("two"))
	r3 := bob.replyWire(id, envelope.TypeStatus, []byte("three"))
	r4 := bob.replyWire(id, envelope.TypeResult, []byte("done"))

	// The gateway delivers 4, 2, 3 and then 4 again.
	wantErr(t, one(t, w.gw.push("alice", r4)), errOutOfOrder)
	if alice.out[id].state != envelope.TypeStatus {
		t.Fatal("a result that jumped the queue changed the task state")
	}
	wantOK(t, w.gw.push("alice", r2))
	wantErr(t, one(t, w.gw.push("alice", r4)), errOutOfOrder)
	wantOK(t, w.gw.push("alice", r3))
	wantOK(t, w.gw.push("alice", r4))
	o := alice.out[id]
	if got := string(o.results[1]) + string(o.results[2]) + string(o.results[3]); got != "twothreedone" || o.state != envelope.TypeResult {
		t.Fatalf("results %q state %v", got, o.state)
	}

	t.Run("a sequence number rewritten in flight", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		id := start(t, w)
		wire := w.dev("bob").replyWire(id, envelope.TypeStatus, []byte("two"))
		bad := mutate(t, wire, func(m *envelope.Message) { m.Header.Seq = 1 })
		wantErr(t, one(t, w.gw.push("alice", bad)), envelope.ErrOpen)
	})
	t.Run("a cancel that overtakes its task", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		alice, bob := w.dev("alice"), w.dev("bob")
		w.gw.onMsg = func(string, []byte) [][]byte { return nil }
		id, _, err := alice.sendTask("bob", []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		w.gw.onMsg = nil
		// The task is still in the gateway's hands; the cancel goes first.
		nk := newKey(t)
		alice.out[id].peerNext, alice.out[id].peerNextID = nk.PublicKey().Bytes(), keyID(nk.PublicKey().Bytes())
		errs, err := alice.cancel(id)
		if err != nil {
			t.Fatal(err)
		}
		wantErr(t, one(t, errs), errUnknownTask)
		if bob.ran != 0 {
			t.Fatal("bob ran a canceled-before-arrival task")
		}
	})
}

func TestDrop(t *testing.T) {
	t.Run("a dropped reply shows as a gap and later ones are held back", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		alice, bob := w.dev("alice"), w.dev("bob")
		id := start(t, w)
		bob.replyWire(id, envelope.TypeStatus, []byte("lost"))
		wire := bob.replyWire(id, envelope.TypeResult, []byte("done"))
		wantErr(t, one(t, w.gw.push("alice", wire)), errOutOfOrder)
		o := alice.out[id]
		if !o.sawAhead || o.state == envelope.TypeResult {
			t.Fatalf("gap not detected: sawAhead %v state %v", o.sawAhead, o.state)
		}
	})
	t.Run("a dropped final result fails the task at its expiry and erases the key", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		alice, bob := w.dev("alice"), w.dev("bob")
		id := start(t, w)
		bob.replyWire(id, envelope.TypeResult, []byte("done"))
		alice.reap(id)
		if alice.out[id].failed {
			t.Fatal("reaped before expiry")
		}
		w.now = w.now.Add(taskTTL)
		alice.reap(id)
		if o := alice.out[id]; !o.failed || o.rsk != nil {
			t.Fatalf("failed %v, key erased %v", o.failed, o.rsk == nil)
		}
	})
	t.Run("a dropped cancel is detected and late replies are refused", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		alice, bob := w.dev("alice"), w.dev("bob")
		id := start(t, w)
		w.gw.onMsg = func(string, []byte) [][]byte { return nil }
		errs, err := alice.cancel(id)
		if err != nil || len(errs) != 0 {
			t.Fatalf("cancel: %v %v", errs, err)
		}
		w.gw.onMsg = nil
		if bob.in[id].canceled {
			t.Fatal("bob saw a cancel the gateway dropped")
		}
		// bob, none the wiser, finishes. Alice must not accept it.
		wantErr(t, one(t, bob.reply(id, envelope.TypeResult, []byte("done"))), errAfterCancel)
		wantErr(t, alice.finishCancel(id), errTimeout)
		w.now = w.now.Add(cancelWait)
		wantErr(t, alice.finishCancel(id), errCancelUnacked)
		o := alice.out[id]
		if o.rsk != nil || !o.failed {
			t.Fatal("reply key survived an unconfirmed cancel")
		}
		wantErr(t, one(t, w.gw.push("alice", w.gw.seen["alice"][len(w.gw.seen["alice"])-1])), errNoKey)
	})
	t.Run("a dropped task leaves a prekey that expires and is erased", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		w.gw.onMsg = func(string, []byte) [][]byte { return nil }
		_, errs, err := w.dev("alice").sendTask("bob", []byte("x"))
		if err != nil || len(errs) != 0 {
			t.Fatalf("%v %v", errs, err)
		}
		bob := w.dev("bob")
		if bob.pool.Outstanding() != 1 {
			t.Fatal("no outstanding prekey")
		}
		w.now = w.now.Add(taskTTL + 3*time.Minute)
		if bob.pool.Outstanding() != 0 {
			t.Fatal("expired prekey still held")
		}
	})
}

func TestSwappedReplies(t *testing.T) {
	setup := func(t *testing.T) (*world, [16]byte, [16]byte) {
		w := newWorld(t, "alice", "bob", "carol")
		id1, errs, err := w.dev("alice").sendTask("bob", []byte("one"))
		if err != nil {
			t.Fatal(err)
		}
		wantOK(t, errs)
		id2, errs, err := w.dev("alice").sendTask("bob", []byte("two"))
		if err != nil {
			t.Fatal(err)
		}
		wantOK(t, errs)
		return w, id1, id2
	}
	t.Run("task one's reply relabelled as task two's", func(t *testing.T) {
		w, id1, id2 := setup(t)
		wire := w.dev("bob").replyWire(id1, envelope.TypeResult, []byte("answer one"))
		bad := mutate(t, wire, func(m *envelope.Message) { m.Header.TaskID = id2 })
		wantErr(t, one(t, w.gw.push("alice", bad)), envelope.ErrOpen)
		if len(w.dev("alice").out[id2].results) != 0 {
			t.Fatal("task two took task one's answer")
		}
	})
	t.Run("the ciphertext of one reply under another's header", func(t *testing.T) {
		w, id1, id2 := setup(t)
		r1 := w.dev("bob").replyWire(id1, envelope.TypeResult, []byte("answer one"))
		r2 := w.dev("bob").replyWire(id2, envelope.TypeResult, []byte("answer two"))
		m1, _ := envelope.Unmarshal(r1)
		bad := mutate(t, r2, func(m *envelope.Message) { m.Enc, m.Ciphertext = m1.Enc, m1.Ciphertext })
		wantErr(t, one(t, w.gw.push("alice", bad)), envelope.ErrOpen)
	})
	t.Run("a reply delivered to the wrong device", func(t *testing.T) {
		w, id1, _ := setup(t)
		wire := w.dev("bob").replyWire(id1, envelope.TypeResult, []byte("answer one"))
		wantErr(t, one(t, w.gw.push("carol", wire)), errMisaddressed)
	})
	t.Run("a root-approved device answers for bob", func(t *testing.T) {
		w, id1, _ := setup(t)
		carol := w.dev("carol")
		// The reply public key travels in the clear in the task header, so any
		// device can seal to it. The signed sender id gives it away.
		task, _ := envelope.Unmarshal(w.gw.seen["bob"][0])
		carol.in[id1] = &inbound{caller: "alice", rpk: task.Header.RPK, expiry: task.Header.Expiry,
			callerLast: w.dev("alice").out[id1].sent, nextKeys: map[string][]byte{}}
		wire := carol.replyWire(id1, envelope.TypeResult, []byte("carol says hi"))
		wantErr(t, one(t, w.gw.push("alice", wire)), errWrongSender)
	})
	t.Run("the signature of another message", func(t *testing.T) {
		w, id1, id2 := setup(t)
		r1 := w.dev("bob").replyWire(id1, envelope.TypeStatus, []byte("one"))
		r2 := w.dev("bob").replyWire(id2, envelope.TypeStatus, []byte("two"))
		m2, _ := envelope.Unmarshal(r2)
		bad := mutate(t, r1, func(m *envelope.Message) { m.Signature = m2.Signature })
		wantErr(t, one(t, w.gw.push("alice", bad)), envelope.ErrBadSignature)
	})
	t.Run("the gateway's state code is only a hint", func(t *testing.T) {
		w, id1, _ := setup(t)
		wire := w.dev("bob").replyWire(id1, envelope.TypeError, []byte("failed"))
		// Claiming COMPLETED means rewriting the signed type; that does not open.
		bad := mutate(t, wire, func(m *envelope.Message) { m.Header.Type = envelope.TypeResult })
		wantErr(t, one(t, w.gw.push("alice", bad)), envelope.ErrOpen)
		wantOK(t, w.gw.push("alice", wire))
		if got := w.dev("alice").out[id1].state; got != envelope.TypeError {
			t.Fatalf("state %v, want the signed ERROR", got)
		}
	})
}

func TestWithheldPrekeys(t *testing.T) {
	t.Run("a withheld prekey reply sends nothing and the issued key expires", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		w.gw.onPrekey = func(string, string, *prekey.Signed) (*prekey.Signed, error) { return nil, nil }
		_, _, err := w.dev("alice").sendTask("bob", []byte("x"))
		wantErr(t, err, errTimeout)
		if w.gw.sent != 0 {
			t.Fatal("alice sent without a prekey")
		}
		bob := w.dev("bob")
		if bob.pool.Outstanding() != 1 {
			t.Fatal("bob should hold the key he issued")
		}
		w.now = w.now.Add(taskTTL + 3*time.Minute)
		if bob.pool.Outstanding() != 0 {
			t.Fatal("withheld prekey outlived the task expiry")
		}
	})
	t.Run("a task held back past expiry is refused and its key is gone", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		bob := w.dev("bob")
		w.gw.onMsg = func(string, []byte) [][]byte { return nil }
		_, _, err := w.dev("alice").sendTask("bob", []byte("secret"))
		if err != nil {
			t.Fatal(err)
		}
		held := w.gw.seen["bob"][0]
		m, _ := envelope.Unmarshal(held)
		raw, _ := hex.DecodeString(m.Header.PrekeyID)
		var pid [16]byte
		copy(pid[:], raw)

		w.now = w.now.Add(taskTTL + 3*time.Minute)
		wantErr(t, one(t, w.gw.push("bob", held)), errExpired)
		// Even without the expiry check, the key no longer exists to open it.
		if err := bob.pool.With(pid, func(*[32]byte) error { return nil }); !errors.Is(err, prekey.ErrExpired) && !errors.Is(err, prekey.ErrUnknown) {
			t.Fatalf("expired prekey still usable: %v", err)
		}
		if bob.ran != 0 {
			t.Fatal("expired task ran")
		}
	})
	t.Run("a task held back and delivered inside the window is accepted (documented residual)", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		w.gw.onMsg = func(string, []byte) [][]byte { return nil }
		_, _, err := w.dev("alice").sendTask("bob", []byte("late but in time"))
		if err != nil {
			t.Fatal(err)
		}
		w.now = w.now.Add(10 * time.Minute)
		wantOK(t, w.gw.push("bob", w.gw.seen["bob"][0]))
		if w.dev("bob").ran != 1 {
			t.Fatal("in-window delayed task should run once")
		}
	})
	t.Run("a processed task cannot be opened again from a captured frame", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		bob := w.dev("bob")
		_, errs, _ := w.dev("alice").sendTask("bob", []byte("secret"))
		wantOK(t, errs)
		captured := w.gw.seen["bob"][0]
		m, _ := envelope.Unmarshal(captured)
		raw, _ := hex.DecodeString(m.Header.PrekeyID)
		var pid [16]byte
		copy(pid[:], raw)
		opened := false
		err := bob.pool.With(pid, func(sc *[32]byte) error {
			opened = true
			_, err := m.Open(sc[:])
			return err
		})
		wantErr(t, err, prekey.ErrConsumed)
		if opened {
			t.Fatal("a consumed key was handed out")
		}
	})
}

func TestReusedPrekeys(t *testing.T) {
	t.Run("an old prekey served for a new request", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		var first *prekey.Signed
		w.gw.onPrekey = func(_, _ string, honest *prekey.Signed) (*prekey.Signed, error) {
			if first == nil {
				first = honest
				return honest, nil
			}
			return first, nil
		}
		if _, _, err := w.dev("alice").fetchPrekey("bob", w.now.Add(taskTTL)); err != nil {
			t.Fatal(err)
		}
		_, _, err := w.dev("alice").fetchPrekey("bob", w.now.Add(taskTTL))
		wantErr(t, err, prekey.ErrMismatch)
	})
	t.Run("alice's prekey served to carol", func(t *testing.T) {
		w := newWorld(t, "alice", "bob", "carol")
		var alices *prekey.Signed
		w.gw.onPrekey = func(from, _ string, honest *prekey.Signed) (*prekey.Signed, error) {
			if from == "alice" {
				alices = honest
				return honest, nil
			}
			return alices, nil
		}
		if _, _, err := w.dev("alice").fetchPrekey("bob", w.now.Add(taskTTL)); err != nil {
			t.Fatal(err)
		}
		_, _, err := w.dev("carol").fetchPrekey("bob", w.now.Add(taskTTL))
		wantErr(t, err, prekey.ErrMismatch)
	})
	t.Run("a prekey cached past its expiry", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		alice := w.dev("alice")
		var cached *prekey.Signed
		w.gw.onPrekey = func(_, _ string, honest *prekey.Signed) (*prekey.Signed, error) {
			if cached == nil {
				cached = honest
			}
			return cached, nil
		}
		if _, _, err := alice.fetchPrekey("bob", w.now.Add(taskTTL)); err != nil {
			t.Fatal(err)
		}
		w.now = w.now.Add(2 * time.Hour)
		_, _, err := alice.fetchPrekey("bob", w.now.Add(taskTTL))
		if err == nil {
			t.Fatal("an expired prekey was accepted")
		}
	})
	t.Run("two tasks sealed to one prekey: only the first opens", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		alice, bob := w.dev("alice"), w.dev("bob")
		s, _, err := alice.fetchPrekey("bob", w.now.Add(taskTTL))
		if err != nil {
			t.Fatal(err)
		}
		_, first := alice.sealTask("bob", s, []byte("first"))
		_, second := alice.sealTask("bob", s, []byte("second"))
		wantOK(t, w.gw.push("bob", first))
		wantErr(t, one(t, w.gw.push("bob", second)), prekey.ErrConsumed)
		if bob.ran != 1 {
			t.Fatalf("ran %d", bob.ran)
		}
		// Reuse also fails after the id is forgotten: the key is gone either way.
		if err := bob.pool.Consume([16]byte(s.ID)); err == nil {
			t.Fatal("prekey consumed twice")
		}
	})
}
