// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// T206: attacks on framing, clocks, direction, reconnects and restarts. Every
// refused frame must leave the target's prekeys, replay table and task state
// exactly as they were, and the honest frame must still go through afterwards.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/receive"
)

// held seals a task from -> to without sending it.
func held(t *testing.T, w *world, from, to string) ([16]byte, []byte) {
	t.Helper()
	d := w.dev(from)
	s, _, err := d.fetchPrekey(to, w.now.Add(taskTTL))
	if err != nil {
		t.Fatal(err)
	}
	return d.sealTask(to, s, []byte("secret task"))
}

// sections returns the [start, end) of each length-prefixed section of a wire
// frame: header, enc, ciphertext, signature.
func sections(t *testing.T, wire []byte) [][2]int {
	t.Helper()
	var out [][2]int
	off := 0
	for range 4 {
		n := int(binary.BigEndian.Uint32(wire[off:]))
		out = append(out, [2]int{off + 4, off + 4 + n})
		off += 4 + n
	}
	if off != len(wire) {
		t.Fatal("not a well-formed frame")
	}
	return out
}

func TestJunkFramesBurnNothing(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	bob := w.dev("bob")
	_, wire := held(t, w, "alice", "bob")
	sec := sections(t, wire)

	flip := func(at int) []byte {
		b := bytes.Clone(wire)
		b[at] ^= 0x01
		return b
	}
	junk := map[string][]byte{
		"empty":                   nil,
		"one byte":                wire[:1],
		"inside a length prefix":  wire[:3],
		"just the first prefix":   wire[:4],
		"half the frame":          wire[:len(wire)/2],
		"one byte short":          wire[:len(wire)-1],
		"signature cut":           wire[:sec[3][0]+10],
		"trailing byte":           append(bytes.Clone(wire), 0),
		"all zeros":               make([]byte, len(wire)),
		"header length wraps":     append([]byte{0xff, 0xff, 0xff, 0xff}, wire[4:]...),
		"flipped header byte":     flip(sec[0][0] + 5),
		"flipped enc byte":        flip(sec[1][0]),
		"flipped ciphertext byte": flip(sec[2][0]),
		"flipped signature byte":  flip(sec[3][0]),
		"random bytes":            w.bytes(len(wire)),
	}
	// A ciphertext one byte over the limit, and a hostile length prefix far
	// beyond the bytes sent: both are refused before anything is buffered or opened.
	big := bytes.Clone(wire[:sec[2][0]-4])
	big = binary.BigEndian.AppendUint32(big, envelope.MaxCiphertextSize+1)
	big = append(big, make([]byte, envelope.MaxCiphertextSize+1)...)
	big = append(big, wire[sec[3][0]-4:]...)
	junk["ciphertext over the limit"] = big
	lie := bytes.Clone(wire)
	binary.BigEndian.PutUint32(lie[sec[2][0]-4:], 1<<31)
	junk["ciphertext length lies"] = lie

	// Framing damage is refused at parse time, before any key or table is touched.
	parse := []string{"empty", "one byte", "inside a length prefix", "just the first prefix", "half the frame", "one byte short",
		"signature cut", "trailing byte", "header length wraps", "ciphertext over the limit", "ciphertext length lies"}
	before := bob.snap()
	for name, f := range junk {
		err := one(t, w.gw.push("bob", f))
		if err == nil {
			t.Fatalf("%s: junk accepted", name)
		}
		for _, p := range parse {
			if p == name {
				wantErr(t, err, envelope.ErrMalformed)
			}
		}
		before.unchanged(t)
	}
	// Nothing above burned the prekey: the real frame still opens.
	wantOK(t, w.gw.push("bob", wire))
	if bob.ran != 1 || bob.pool.Outstanding() != 0 {
		t.Fatalf("ran %d, outstanding %d", bob.ran, bob.pool.Outstanding())
	}
}

func TestSignedButUnopenableBurnsNothing(t *testing.T) {
	// Authentic sender, genuine prekey id, but the ciphertext is for another
	// key: this passes the signature check, fails the open, and must leave the
	// prekey and the replay table as they were.
	w := newWorld(t, "alice", "bob")
	bob := w.dev("bob")
	s, _, err := w.dev("alice").fetchPrekey("bob", w.now.Add(taskTTL))
	if err != nil {
		t.Fatal(err)
	}
	wrong := *s
	wrong.PublicKey = w.key().PublicKey().Bytes()
	_, bad := w.dev("alice").sealTask("bob", &wrong, []byte("x"))
	before := bob.snap()
	wantErr(t, one(t, w.gw.push("bob", bad)), envelope.ErrOpen)
	before.unchanged(t)
	_, good := w.dev("alice").sealTask("bob", s, []byte("y"))
	wantOK(t, w.gw.push("bob", good))
}

func TestClocks(t *testing.T) {
	t.Run("a task from the future is refused and not burned", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		bob := w.dev("bob")
		_, wire := held(t, w, "alice", "bob")
		bob.skew = -(receive.DefaultSkew + time.Minute) // bob's clock is behind alice's
		before := bob.snap()
		wantErr(t, one(t, w.gw.push("bob", wire)), receive.ErrExpired)
		before.unchanged(t)
		bob.skew = -(receive.DefaultSkew - time.Minute) // inside the allowed skew
		wantOK(t, w.gw.push("bob", wire))
	})
	t.Run("a task at the instant of its expiry is refused", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		bob := w.dev("bob")
		_, wire := held(t, w, "alice", "bob")
		bob.skew = taskTTL
		before := bob.snap()
		wantErr(t, one(t, w.gw.push("bob", wire)), receive.ErrExpired)
		if bob.ran != 0 || before.replays != 0 {
			t.Fatal("an expired task ran or was recorded")
		}
	})
	t.Run("a reply past its expiry is refused", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		id := start(t, w)
		wire := w.dev("bob").replyWire(id, envelope.TypeStatus, []byte("late"))
		w.now = w.now.Add(taskTTL)
		wantErr(t, one(t, w.gw.push("alice", wire)), errExpired)
		if len(w.dev("alice").out[id].results) != 1 {
			t.Fatal("alice took a reply past its expiry")
		}
	})
	t.Run("a prekey from a clock far ahead is not trusted", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		w.dev("bob").skew = prekey.DefaultSkew + time.Minute
		_, _, err := w.dev("alice").fetchPrekey("bob", w.now.Add(taskTTL))
		if err == nil {
			t.Fatal("a prekey created in the future was accepted")
		}
	})
}

func TestWrongDirection(t *testing.T) {
	t.Run("a reply-type frame for a task this device received", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		alice, bob := w.dev("alice"), w.dev("bob")
		id := start(t, w)
		// alice, who owns the task, sends bob a RESULT for it, sealed to the
		// follow-up key bob gave her. Bob never sent that task outbound.
		o := alice.out[id]
		h := envelope.Header{Tenant: tenant, SenderDevice: "alice", SenderKeyID: keyID(alice.bind.SigningKey), BindingVersion: 1,
			TargetDevice: "bob", PrekeyID: o.peerNextID, TaskID: id, ContextID: o.ctx, Seq: 1, Type: envelope.TypeResult,
			IssuedAt: w.now, Expiry: o.expiry, PrevHash: o.sent}
		m, err := envelope.Seal(alice.sign, o.peerNext, h, []byte("forged"))
		if err != nil {
			t.Fatal(err)
		}
		before := bob.snap()
		wantErr(t, one(t, w.gw.push("bob", m.Marshal())), errUnknownTask)
		before.unchanged(t)
	})
	t.Run("a task sealed to a prekey the target never issued", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		alice := w.dev("alice")
		s, err := w.dev("bob").issue("alice", w.bytes(16), w.now.Add(taskTTL)) // bob's own prekey, not alice's
		if err != nil {
			t.Fatal(err)
		}
		_, wire := w.dev("bob").sealTask("alice", s, []byte("x"))
		before := alice.snap()
		wantErr(t, one(t, w.gw.push("alice", wire)), receive.ErrDropped)
		before.unchanged(t)
	})
	t.Run("a cancel from a device that is not the caller, with a leaked follow-up key", func(t *testing.T) {
		w := newWorld(t, "alice", "bob", "carol")
		alice, bob, carol := w.dev("alice"), w.dev("bob"), w.dev("carol")
		id := start(t, w)
		o := alice.out[id]
		h := envelope.Header{Tenant: tenant, SenderDevice: "carol", SenderKeyID: keyID(carol.bind.SigningKey), BindingVersion: 1,
			TargetDevice: "bob", PrekeyID: o.peerNextID, TaskID: id, ContextID: o.ctx, Seq: 1, Type: envelope.TypeCancel,
			IssuedAt: w.now, Expiry: o.expiry, PrevHash: o.sent}
		m, err := envelope.Seal(carol.sign, o.peerNext, h, nil)
		if err != nil {
			t.Fatal(err)
		}
		before := bob.snap()
		wantErr(t, one(t, w.gw.push("bob", m.Marshal())), errWrongSender)
		before.unchanged(t)
		if bob.in[id].canceled {
			t.Fatal("a stranger canceled alice's task")
		}
	})
	t.Run("a task for another tenant", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		_, wire := held(t, w, "alice", "bob")
		bad := mutate(t, wire, func(m *envelope.Message) { m.Header.Tenant = "other" })
		before := w.dev("bob").snap()
		wantErr(t, one(t, w.gw.push("bob", bad)), receive.ErrNotForUs)
		before.unchanged(t)
	})
}

func TestSenderPolicy(t *testing.T) {
	t.Run("a revoked sender", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		bob := w.dev("bob")
		_, wire := held(t, w, "alice", "bob")
		bob.revoked["alice"] = true
		before := bob.snap()
		wantErr(t, one(t, w.gw.push("bob", wire)), receive.ErrRejected)
		before.unchanged(t)
		bob.revoked["alice"] = false
		wantOK(t, w.gw.push("bob", wire))
	})
	t.Run("an owner the allowlist refuses", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		bob := w.dev("bob")
		_, wire := held(t, w, "alice", "bob")
		bob.denied["alice@acme.test"] = true
		before := bob.snap()
		wantErr(t, one(t, w.gw.push("bob", wire)), receive.ErrRejected)
		before.unchanged(t)
	})
	t.Run("a binding version the sender's binding does not carry", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		alice := w.dev("alice")
		s, _, err := alice.fetchPrekey("bob", w.now.Add(taskTTL))
		if err != nil {
			t.Fatal(err)
		}
		// Signed with alice's real key, so only the version check can refuse it.
		stale := *alice
		b := *alice.bind
		b.Version = 2
		stale.bind = &b
		_, wire := stale.sealTask("bob", s, []byte("x"))
		before := w.dev("bob").snap()
		wantErr(t, one(t, w.gw.push("bob", wire)), receive.ErrRejected)
		before.unchanged(t)
	})
}

func TestReconnectAndRestart(t *testing.T) {
	t.Run("the whole backlog redelivered after a reconnect, twice", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		alice, bob := w.dev("alice"), w.dev("bob")
		id := start(t, w)
		wantOK(t, bob.reply(id, envelope.TypeResult, []byte("done")))
		bobBefore, aliceBefore := bob.snap(), alice.snap()
		results := len(alice.out[id].results)
		for range 2 {
			for _, to := range []string{"bob", "alice"} {
				for _, f := range append([][]byte(nil), w.gw.seen[to]...) {
					if err := one(t, w.gw.push(to, f)); err == nil {
						t.Fatalf("a redelivered frame for %s was accepted", to)
					}
				}
			}
		}
		bobBefore.unchanged(t)
		aliceBefore.unchanged(t)
		if len(alice.out[id].results) != results {
			t.Fatal("redelivery added results")
		}
	})
	t.Run("a captured task after the target restarts", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		bob := w.dev("bob")
		_, wire := held(t, w, "alice", "bob")
		bob.restart() // the prekey private key died with the process
		before := bob.snap()
		err := one(t, w.gw.push("bob", wire))
		wantErr(t, err, receive.ErrDropped)
		wantErr(t, err, prekey.ErrUnknown)
		before.unchanged(t)
		// The restarted daemon still serves new tasks.
		id, errs, err2 := w.dev("alice").sendTask("bob", []byte("after"))
		if err2 != nil {
			t.Fatal(err2)
		}
		wantOK(t, errs)
		if string(bob.in[id].content) != "after" {
			t.Fatal("restarted daemon did not run the new task")
		}
	})
	t.Run("a delivered task replayed after the target restarts", func(t *testing.T) {
		w := newWorld(t, "alice", "bob")
		bob := w.dev("bob")
		_, errs, err := w.dev("alice").sendTask("bob", []byte("pay"))
		if err != nil {
			t.Fatal(err)
		}
		wantOK(t, errs)
		bob.restart() // replay table is empty again; the key is gone, so it cannot run
		wantErr(t, one(t, w.gw.push("bob", w.gw.seen["bob"][0])), prekey.ErrUnknown)
		if bob.ran != 0 || bob.replays.Len() != 0 {
			t.Fatalf("ran %d, replay entries %d", bob.ran, bob.replays.Len())
		}
	})
}

func TestQuota(t *testing.T) {
	// A flood of authentic tasks to prekeys that do not exist cannot fill the
	// replay table: each is refused at the open and its entry taken back.
	w := newWorld(t, "alice", "bob")
	bob := w.dev("bob")
	s, _, err := w.dev("alice").fetchPrekey("bob", w.now.Add(taskTTL))
	if err != nil {
		t.Fatal(err)
	}
	wrong := *s
	wrong.PublicKey = w.key().PublicKey().Bytes()
	for i := range 50 {
		_, bad := w.dev("alice").sealTask("bob", &wrong, []byte(fmt.Sprint(i)))
		wantErr(t, one(t, w.gw.push("bob", bad)), envelope.ErrOpen)
	}
	if bob.replays.Len() != 0 || bob.pool.Outstanding() != 1 {
		t.Fatalf("replay entries %d, outstanding %d", bob.replays.Len(), bob.pool.Outstanding())
	}
}
