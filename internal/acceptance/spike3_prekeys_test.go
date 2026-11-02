// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// T208 (spike 3, prekeys): crash points end in a clean failure and a
// successful resend, and junk frames cannot burn keys. The caller side is
// driven as the daemon would drive it (request a prekey, verify it, seal,
// marshal to wire bytes); the receiver is the real receive path.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/receive"
	"github.com/kalahroudi/parley/internal/replay"
)

const taskText = "review this diff"

type crashWorld struct {
	t       *testing.T
	now     time.Time
	callerK ed25519.PrivateKey
	bind    *binding.Signed
	rootPub ed25519.PublicKey
	targetK ed25519.PrivateKey
	// Per "process": replaced on restart.
	pool  *prekey.Pool
	table *replay.Table
	rcv   *receive.Receiver
	fault func(receive.Stage) error
	runs  [][]byte // plaintexts execute saw
	acks  int
}

func (w *crashWorld) clock() time.Time { return w.now }

func newCrashWorld(t *testing.T) *crashWorld {
	t.Helper()
	w := &crashWorld{t: t, now: t0}
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	w.rootPub = rootPub
	cpub, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	w.callerK = cpriv
	var err error
	w.bind, err = binding.Sign(rootPriv, binding.Binding{Tenant: "acme", Owner: "alice@acme.test", DeviceID: "caller",
		SigningKey: cpub, Version: 1, NotAfter: t0.Add(binding.Lifetime)})
	if err != nil {
		t.Fatal(err)
	}
	_, w.targetK, _ = ed25519.GenerateKey(rand.Reader)
	w.restart()
	return w
}

// restart models the target daemon dying and coming back: a fresh pool with
// new random keys and an empty replay table.
func (w *crashWorld) restart() {
	w.t.Helper()
	if w.pool != nil {
		w.pool.Close()
	}
	var err error
	w.pool, err = prekey.New(prekey.Config{Tenant: "acme", DeviceID: "target", SigningKeyID: "k-t", BindingVersion: 1,
		Signer: w.targetK, AllowUnlocked: true, SweepEvery: time.Hour, Now: w.clock})
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(w.pool.Close)
	w.table = replay.New(replay.Config{Now: w.clock})
	tr, err := binding.NewTracker(w.rootPub, nil)
	if err != nil {
		w.t.Fatal(err)
	}
	w.rcv, err = receive.New(receive.Config{Tenant: "acme", Device: "target", Pool: w.pool, Replay: w.table, Bindings: tr,
		Lookup:  func(d string) (*binding.Signed, error) { return w.bind, nil },
		Revoked: func(string) bool { return false },
		Allow:   func(o string) bool { return o == "alice@acme.test" },
		Now:     w.clock,
		Fault: func(st receive.Stage) error {
			if w.fault != nil {
				return w.fault(st)
			}
			return nil
		}})
	if err != nil {
		w.t.Fatal(err)
	}
}

// send is one caller attempt: a fresh prekey, a fresh task id, wire bytes.
func (w *crashWorld) send(taskID [16]byte) []byte {
	w.t.Helper()
	nonce := make([]byte, 16)
	rand.Read(nonce)
	exp := w.now.Add(15 * time.Minute)
	sp, err := w.pool.Issue(prekey.Request{Caller: "caller", Nonce: nonce, TaskExpiry: exp})
	if err != nil {
		w.t.Fatal(err)
	}
	tpub := w.targetK.Public().(ed25519.PublicKey)
	if err := prekey.Verify(tpub, sp, prekey.Expect{Tenant: "acme", DeviceID: "target", SigningKeyID: "k-t",
		Caller: "caller", Nonce: nonce, BindingVersion: 1, Now: w.now}); err != nil {
		w.t.Fatal("caller refuses the prekey:", err)
	}
	h := envelope.Header{Tenant: "acme", SenderDevice: "caller", SenderKeyID: "k-c", BindingVersion: 1,
		TargetDevice: "target", PrekeyID: receive.PrekeyID(sp.ID), ContextID: "ctx", TaskID: taskID,
		Type: envelope.TypeTask, IssuedAt: w.now, Expiry: exp, RPK: bytes.Repeat([]byte{9}, 32), Prekey: sp.Encode()}
	m, err := envelope.SealPadded(w.callerK, sp.PublicKey, h, []byte(taskText))
	if err != nil {
		w.t.Fatal(err)
	}
	return m.Marshal()
}

// deliver parses wire bytes and runs the receive path.
func (w *crashWorld) deliver(wire []byte) error {
	m, err := envelope.Unmarshal(wire)
	if err != nil {
		return err
	}
	return w.rcv.Receive(m,
		func() error { w.acks++; return nil },
		func(d receive.Delivered) error {
			pt, err := envelope.Unpad(d.Plaintext)
			if err != nil {
				return err
			}
			w.runs = append(w.runs, bytes.Clone(pt))
			return nil
		})
}

func (w *crashWorld) wantRuns(n int) {
	w.t.Helper()
	if len(w.runs) != n {
		w.t.Fatalf("executed %d times, want %d", len(w.runs), n)
	}
	for _, r := range w.runs {
		if string(r) != taskText {
			w.t.Fatalf("executed with %q", r)
		}
	}
}

// A crash at any point before execute starts ends in a clean failure: nothing
// ran, and a resend from the caller (fresh prekey, same task id) runs exactly
// once. This covers the plan's two named points, between open and ack
// (StageOpened, StageErased) and between erase and execute (StageErased,
// StageAcked), plus the stages around them. Each crash is checked both as an
// in-process abort and as a full restart of the target.
func TestCrashPointsFailCleanAndResend(t *testing.T) {
	stages := []struct {
		name   string
		st     receive.Stage
		erased bool
		acked  int
	}{
		{"authenticated", receive.StageAuthenticated, false, 0},
		{"recorded", receive.StageRecorded, false, 0},
		{"open-to-erase", receive.StageOpened, false, 0},
		{"erase-to-ack", receive.StageErased, true, 0},
		{"ack-to-execute", receive.StageAcked, true, 1},
	}
	for _, c := range stages {
		for _, restart := range []bool{false, true} {
			name := c.name + "/inprocess"
			if restart {
				name = c.name + "/restart"
			}
			t.Run(name, func(t *testing.T) {
				w := newCrashWorld(t)
				var task [16]byte
				rand.Read(task[:])
				first := w.send(task)

				w.fault = func(st receive.Stage) error {
					if st == c.st {
						return errors.New("crash")
					}
					return nil
				}
				if err := w.deliver(first); !errors.Is(err, receive.ErrFault) {
					t.Fatalf("crash not reported: %v", err)
				}
				w.fault = nil
				w.wantRuns(0)
				if w.acks != c.acked {
					t.Fatalf("acks=%d want %d", w.acks, c.acked)
				}
				if got := w.pool.Outstanding() == 0; got != c.erased {
					t.Fatalf("key erased=%v want %v", got, c.erased)
				}

				if restart {
					w.restart()
					// The captured frame is unopenable now, and leaves no trace.
					if err := w.deliver(first); !errors.Is(err, receive.ErrDropped) || w.table.Len() != 0 {
						t.Fatalf("after restart: %v len=%d", err, w.table.Len())
					}
				} else if c.erased {
					// Same process: the frame is dropped, never re-run.
					if err := w.deliver(first); !errors.Is(err, receive.ErrDropped) {
						t.Fatalf("redelivery: %v", err)
					}
				}
				w.wantRuns(0)

				// The caller's side sees the failure and resends with a fresh prekey.
				if err := w.deliver(w.send(task)); err != nil {
					t.Fatal("resend:", err)
				}
				w.wantRuns(1)
				// The only key left is the first, unused prekey, which a
				// surviving process keeps until it expires.
				want := 0
				if !c.erased && !restart {
					want = 1
				}
				if got := w.pool.Outstanding(); got != want {
					t.Fatalf("outstanding keys=%d want %d", got, want)
				}
				// The task id has now run: another send under it is dropped.
				if err := w.deliver(w.send(task)); !errors.Is(err, receive.ErrDropped) {
					t.Fatalf("task id ran twice: %v", err)
				}
				w.wantRuns(1)
			})
		}
	}
}

// Junk of every kind, sent before the real frame, cannot burn the key, fill the
// replay table or stop the real frame from running.
func TestJunkFramesCannotBurnKeys(t *testing.T) {
	w := newCrashWorld(t)
	var task [16]byte
	rand.Read(task[:])
	good := w.send(task)
	m, _ := envelope.Unmarshal(good)

	// Not a frame at all.
	garbage := make([]byte, 300)
	rand.Read(garbage)
	// Bit flips in every part of a real frame.
	flip := func(mod func(*envelope.Message)) []byte {
		c := *m
		c.Enc, c.Ciphertext, c.Signature = bytes.Clone(m.Enc), bytes.Clone(m.Ciphertext), bytes.Clone(m.Signature)
		mod(&c)
		return c.Marshal()
	}
	// A frame signed by someone who is not the bound sender, aimed at our prekey.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := envelope.Unmarshal(good)
	forged := *sp
	forged.Signature = ed25519.Sign(stranger, forged.Transcript())
	// A well-formed frame naming a prekey we never issued.
	unknown := flip(func(c *envelope.Message) { c.Header.PrekeyID = receive.PrekeyID([16]byte{1}) })
	wrongTarget := flip(func(c *envelope.Message) { c.Header.TargetDevice = "someone-else" })
	wrongTenant := flip(func(c *envelope.Message) { c.Header.Tenant = "other" })

	junk := map[string][]byte{
		"garbage":      garbage,
		"truncated":    good[:len(good)/2],
		"flip-ct":      flip(func(c *envelope.Message) { c.Ciphertext[0] ^= 1 }),
		"flip-enc":     flip(func(c *envelope.Message) { c.Enc[0] ^= 1 }),
		"flip-sig":     flip(func(c *envelope.Message) { c.Signature[0] ^= 1 }),
		"bad-sender":   forged.Marshal(),
		"unknown-key":  unknown,
		"wrong-target": wrongTarget,
		"wrong-tenant": wrongTenant,
	}
	for round := 0; round < 50; round++ {
		for name, wire := range junk {
			if err := w.deliver(wire); err == nil {
				t.Fatalf("%s accepted", name)
			}
			if w.pool.Outstanding() != 1 || w.table.Len() != 0 || w.acks != 0 {
				t.Fatalf("%s round %d: outstanding=%d replay=%d acks=%d", name, round, w.pool.Outstanding(), w.table.Len(), w.acks)
			}
		}
	}
	w.wantRuns(0)

	if err := w.deliver(good); err != nil {
		t.Fatal("real frame after junk:", err)
	}
	w.wantRuns(1)
	if err := w.deliver(good); !errors.Is(err, receive.ErrDropped) {
		t.Fatalf("redelivery: %v", err)
	}
	w.wantRuns(1)
}
