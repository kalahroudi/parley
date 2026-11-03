// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// T208 (spike 3, prekeys). The plan's prekey acceptance list, one test each:
//
//	(a) TestCrashPointsFailCleanAndResend   crash between open and ack, and between erase and execute
//	(b) TestPrekeyExpiresWhileSenderWaits   a prekey that expired while the sender waited is refused
//	(c) TestJunkFramesCannotBurnKeys        junk frames cannot burn keys
//	(d) TestRedeliveredFrameIsDropped       a redelivered frame is dropped
//	(e) TestPrekeyRequestFloodIsLimited     a prekey request flood is rate-limited (device side)
//	(h) TestDiskCloneAndBackupHoldNoKeys    a disk clone or restored backup holds no usable keys
//	(i) TestRestartInvariant                replay safety across a restart relies on memory-only prekeys
//
// (f) the five-message follow-up chain, (g) a late reply after CANCEL and the
// gateway-side flood limit are not testable yet; they are the named pending
// tests at the bottom of this file, which fail once their task is ticked.
//
// A crash is modelled the way a kill is: the old pool, replay table and
// receiver are abandoned (never closed, never read again) and the daemon is
// rebuilt from the state directory alone. The state directory holds the one
// thing the real daemon persists on this path, the binding rollback store
// (internal/binding FileStore). Nothing else is carried over, so a test cannot
// pass by accident of shared memory. The caller side is driven as the daemon
// would drive it (request a prekey, verify it, seal, marshal to wire bytes);
// the receiver is the real receive path.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	dir     string // the target's state directory: what survives a crash
	pools   []*prekey.Pool
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
	w := &crashWorld{t: t, now: t0, dir: t.TempDir()}
	// The daemon's working directory is its state directory, so a stray
	// relative-path write by any package lands where the key scans look.
	t.Chdir(w.dir)
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

// onCopyOf returns the same target and caller identities running from a copy
// of w's state directory, as after a disk clone or a restored backup. Its
// memory starts empty, like any other boot.
func (w *crashWorld) onCopyOf(dir string) *crashWorld {
	w.t.Helper()
	copyTree(w.t, w.dir, dir)
	c := *w
	c.dir, c.pools, c.pool, c.table, c.rcv, c.fault, c.runs, c.acks = dir, nil, nil, nil, nil, nil, nil, 0
	c.restart()
	return &c
}

// restart models the target daemon being killed and started again. The old
// process is abandoned, not shut down: nothing is closed or zeroed on its
// behalf. The new one gets a fresh pool with new random keys, an empty replay
// table and whatever the state directory holds.
func (w *crashWorld) restart() {
	w.t.Helper()
	var err error
	w.pool, err = prekey.New(prekey.Config{Tenant: "acme", DeviceID: "target", SigningKeyID: "k-t", BindingVersion: 1,
		Signer: w.targetK, AllowUnlocked: true, SweepEvery: time.Hour, Now: w.clock})
	if err != nil {
		w.t.Fatal(err)
	}
	w.pools = append(w.pools, w.pool)
	w.t.Cleanup(w.pool.Close)
	w.table = replay.New(replay.Config{Now: w.clock})
	tr, err := binding.NewTracker(w.rootPub, binding.NewFileStore(filepath.Join(w.dir, "bindings.json")))
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

// fetch is the caller asking for a prekey and refusing one it cannot trust.
func (w *crashWorld) fetch() (*prekey.Signed, time.Time) {
	w.t.Helper()
	nonce := make([]byte, 16)
	rand.Read(nonce)
	exp := w.now.Add(15 * time.Minute)
	sp, err := w.pool.Issue(prekey.Request{Caller: "caller", Nonce: nonce, TaskExpiry: exp})
	if err != nil {
		w.t.Fatal(err)
	}
	if err := prekey.Verify(w.targetK.Public().(ed25519.PublicKey), sp, prekey.Expect{Tenant: "acme", DeviceID: "target",
		SigningKeyID: "k-t", Caller: "caller", Nonce: nonce, BindingVersion: 1, Now: w.now}); err != nil {
		w.t.Fatal("caller refuses the prekey:", err)
	}
	return sp, exp
}

// seal builds the wire bytes for one task sealed to pub, addressed to sp.
func (w *crashWorld) seal(sp *prekey.Signed, pub []byte, taskID [16]byte, exp time.Time) []byte {
	w.t.Helper()
	h := envelope.Header{Tenant: "acme", SenderDevice: "caller", SenderKeyID: "k-c", BindingVersion: 1,
		TargetDevice: "target", PrekeyID: receive.PrekeyID(sp.ID), ContextID: "ctx", TaskID: taskID,
		Type: envelope.TypeTask, IssuedAt: w.now, Expiry: exp, RPK: bytes.Repeat([]byte{9}, 32), Prekey: sp.Encode()}
	m, err := envelope.SealPadded(w.callerK, pub, h, []byte(taskText))
	if err != nil {
		w.t.Fatal(err)
	}
	return m.Marshal()
}

// send is one caller attempt: a fresh prekey, then wire bytes.
func (w *crashWorld) send(taskID [16]byte) []byte {
	w.t.Helper()
	sp, exp := w.fetch()
	return w.seal(sp, sp.PublicKey, taskID, exp)
}

func newTask() (id [16]byte) { rand.Read(id[:]); return }

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

// wantState checks the three things a refused frame must leave alone.
func (w *crashWorld) wantState(outstanding, replays, acks int) {
	w.t.Helper()
	if got := w.pool.Outstanding(); got != outstanding {
		w.t.Fatalf("outstanding keys=%d want %d", got, outstanding)
	}
	if got := w.table.Len(); got != replays {
		w.t.Fatalf("replay entries=%d want %d", got, replays)
	}
	if w.acks != acks {
		w.t.Fatalf("acks=%d want %d", w.acks, acks)
	}
}

// scalars borrows the raw private keys of every live prekey, for scanning.
func scalars(t *testing.T, p *prekey.Pool, ids ...[16]byte) [][]byte {
	t.Helper()
	var out [][]byte
	for _, id := range ids {
		if err := p.With(id, func(sk *[32]byte) error { out = append(out, bytes.Clone(sk[:])); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// copyTree copies the regular files under src into dst, as a disk clone does.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// filesHolding returns the files under dir whose bytes contain any needle.
func filesHolding(t *testing.T, dir string, needles ...[]byte) []string {
	t.Helper()
	var hits []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, n := range needles {
			if bytes.Contains(b, n) {
				hits = append(hits, p)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

// (a) A crash at any point before execute starts ends in a clean failure:
// nothing ran, and a resend from the caller (fresh prekey, same task id) runs
// exactly once. This covers the plan's two named points, between open and ack
// (StageOpened, StageErased) and between erase and execute (StageErased,
// StageAcked), plus the stages around them. Each crash is checked both as an
// in-process abort and as a kill of the target followed by a rebuild from its
// state directory.
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
				task := newTask()
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
				// Whatever the stage, no replay entry outlives the abort: the
				// resend must not meet the ghost of the first attempt.
				if w.table.Len() != 0 {
					t.Fatalf("replay entries=%d after the crash", w.table.Len())
				}

				if restart {
					w.restart()
					// The captured frame is unopenable now, and leaves no trace.
					err := w.deliver(first)
					if !errors.Is(err, receive.ErrDropped) || !errors.Is(err, prekey.ErrUnknown) || w.table.Len() != 0 {
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

// A crash during execute itself is the other side of the line: the task may
// have run, so the replay entry stays and the same frame cannot run again; a
// restart afterwards cannot reopen it either.
func TestCrashDuringExecuteDoesNotRunTwice(t *testing.T) {
	w := newCrashWorld(t)
	task := newTask()
	first := w.send(task)
	m, _ := envelope.Unmarshal(first)
	err := w.rcv.Receive(m, func() error { w.acks++; return nil },
		func(receive.Delivered) error { return errors.New("died mid-task") })
	if err == nil || w.table.Len() != 1 || w.acks != 1 {
		t.Fatalf("err=%v replay=%d acks=%d", err, w.table.Len(), w.acks)
	}
	if err := w.deliver(first); !errors.Is(err, receive.ErrDropped) {
		t.Fatalf("redelivery: %v", err)
	}
	w.restart()
	if err := w.deliver(first); !errors.Is(err, receive.ErrDropped) {
		t.Fatalf("redelivery after restart: %v", err)
	}
	w.wantRuns(0)
}

// (b) A prekey that expires while the sender waits is refused, on both sides:
// the caller will not seal to it, and a frame sealed to it anyway is refused by
// the target, burns nothing and leaves nothing behind.
func TestPrekeyExpiresWhileSenderWaits(t *testing.T) {
	t.Run("the caller refuses an expired prekey", func(t *testing.T) {
		w := newCrashWorld(t)
		nonce := []byte("0123456789abcdef")
		sp, err := w.pool.Issue(prekey.Request{Caller: "caller", Nonce: nonce, TaskExpiry: w.now.Add(15 * time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		expect := prekey.Expect{Tenant: "acme", DeviceID: "target", SigningKeyID: "k-t", Caller: "caller", Nonce: nonce,
			BindingVersion: 1, Now: sp.ExpiresAt.Add(-time.Second)}
		pub := w.targetK.Public().(ed25519.PublicKey)
		if err := prekey.Verify(pub, sp, expect); err != nil {
			t.Fatal("a prekey one second from expiry must still verify:", err)
		}
		expect.Now = sp.ExpiresAt
		if err := prekey.Verify(pub, sp, expect); !errors.Is(err, prekey.ErrExpired) {
			t.Fatalf("expired prekey verified: %v", err)
		}
	})
	t.Run("the target refuses a task whose own expiry passed", func(t *testing.T) {
		w := newCrashWorld(t)
		wire := w.send(newTask())
		w.now = w.now.Add(16 * time.Minute) // past the task expiry, inside the prekey's skew allowance
		if err := w.deliver(wire); !errors.Is(err, receive.ErrExpired) {
			t.Fatalf("late task: %v", err)
		}
		w.wantRuns(0)
		w.wantState(1, 0, 0)
	})
	t.Run("the target refuses a frame sealed to an expired prekey", func(t *testing.T) {
		// The sender claims a longer task expiry than the prekey allows, so
		// only the prekey's own expiry can stop it.
		w := newCrashWorld(t)
		sp, _ := w.fetch()
		wire := w.seal(sp, sp.PublicKey, newTask(), w.now.Add(time.Hour))
		w.now = sp.ExpiresAt
		err := w.deliver(wire)
		if !errors.Is(err, receive.ErrExpired) || !errors.Is(err, prekey.ErrExpired) {
			t.Fatalf("frame to an expired prekey: %v", err)
		}
		w.wantRuns(0)
		w.wantState(0, 0, 0) // the key was zeroed, nothing recorded
		if err := w.deliver(wire); !errors.Is(err, receive.ErrDropped) && !errors.Is(err, receive.ErrExpired) {
			t.Fatalf("second delivery: %v", err)
		}
		// A fresh send still works.
		if err := w.deliver(w.send(newTask())); err != nil {
			t.Fatal("resend:", err)
		}
		w.wantRuns(1)
	})
}

// (c) Junk of every kind, sent before the real frame, cannot burn the key, fill
// the replay table or stop the real frame from running. The "signed but sealed
// to another key" frame is the one that matters most: it is authentic, so it
// reaches the replay table and the open, and only the open failing keeps the
// key.
func TestJunkFramesCannotBurnKeys(t *testing.T) {
	w := newCrashWorld(t)
	task := newTask()
	sp, exp := w.fetch()
	good := w.seal(sp, sp.PublicKey, task, exp)
	m, _ := envelope.Unmarshal(good)

	garbage := make([]byte, 300)
	rand.Read(garbage)
	flip := func(mod func(*envelope.Message)) []byte {
		c := *m
		c.Enc, c.Ciphertext, c.Signature = bytes.Clone(m.Enc), bytes.Clone(m.Ciphertext), bytes.Clone(m.Signature)
		mod(&c)
		return c.Marshal()
	}
	// A frame signed by someone who is not the bound sender, aimed at our prekey.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	forged := *m
	forged.Signature = ed25519.Sign(stranger, forged.Transcript())
	// Authentic (the bound sender signed it), naming our live prekey, but
	// sealed to some other key: the open must fail and the key must survive.
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	wrongKey := w.seal(sp, other.PublicKey().Bytes(), task, exp)
	// A well-formed frame naming a prekey we never issued.
	unknown := flip(func(c *envelope.Message) { c.Header.PrekeyID = receive.PrekeyID([16]byte{1}) })
	wrongTarget := flip(func(c *envelope.Message) { c.Header.TargetDevice = "someone-else" })
	wrongTenant := flip(func(c *envelope.Message) { c.Header.Tenant = "other" })

	junk := map[string][]byte{
		"garbage":       garbage,
		"truncated":     good[:len(good)/2],
		"flip-ct":       flip(func(c *envelope.Message) { c.Ciphertext[0] ^= 1 }),
		"flip-enc":      flip(func(c *envelope.Message) { c.Enc[0] ^= 1 }),
		"flip-sig":      flip(func(c *envelope.Message) { c.Signature[0] ^= 1 }),
		"bad-sender":    forged.Marshal(),
		"unknown-key":   unknown,
		"wrong-target":  wrongTarget,
		"wrong-tenant":  wrongTenant,
		"signed-wrongk": wrongKey,
	}
	for round := 0; round < 50; round++ {
		for name, wire := range junk {
			if err := w.deliver(wire); err == nil {
				t.Fatalf("%s accepted", name)
			}
			w.wantStateNamed(name, round, 1, 0, 0)
		}
	}
	w.wantRuns(0)

	if err := w.deliver(good); err != nil {
		t.Fatal("real frame after junk:", err)
	}
	w.wantRuns(1)
}

func (w *crashWorld) wantStateNamed(name string, round, outstanding, replays, acks int) {
	w.t.Helper()
	if w.pool.Outstanding() != outstanding || w.table.Len() != replays || w.acks != acks {
		w.t.Fatalf("%s round %d: outstanding=%d replay=%d acks=%d", name, round, w.pool.Outstanding(), w.table.Len(), w.acks)
	}
}

// (d) A redelivered frame is dropped: after it ran, after it failed halfway,
// and a hundred times in a row.
func TestRedeliveredFrameIsDropped(t *testing.T) {
	w := newCrashWorld(t)
	good := w.send(newTask())
	if err := w.deliver(good); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err := w.deliver(good); !errors.Is(err, receive.ErrDropped) {
			t.Fatalf("redelivery %d: %v", i, err)
		}
	}
	w.wantRuns(1)
	w.wantState(0, 1, 1)
}

// (e) A prekey request flood is rate-limited on the device: one caller can hold
// only so many unused prekeys, the limit does not starve other callers, and
// spending or expiring a key frees a place. The gateway-side limit is T305.
func TestPrekeyRequestFloodIsLimited(t *testing.T) {
	w := newCrashWorld(t)
	ask := func(caller string) (*prekey.Signed, error) {
		n := make([]byte, 16)
		rand.Read(n)
		return w.pool.Issue(prekey.Request{Caller: caller, Nonce: n, TaskExpiry: w.now.Add(15 * time.Minute)})
	}
	var first *prekey.Signed
	for i := 0; i < prekey.DefaultPerCaller; i++ {
		sp, err := ask("flooder")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if first == nil {
			first = sp
		}
	}
	for i := 0; i < 1000; i++ {
		if _, err := ask("flooder"); !errors.Is(err, prekey.ErrRateLimited) {
			t.Fatalf("flood request %d: %v", i, err)
		}
	}
	if got := w.pool.Outstanding(); got != prekey.DefaultPerCaller {
		t.Fatalf("flood grew the pool to %d", got)
	}
	if _, err := ask("someone-else"); err != nil {
		t.Fatal("the flood starved another caller:", err)
	}
	if err := w.pool.Consume(first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ask("flooder"); err != nil {
		t.Fatal("a spent key did not free a place:", err)
	}
	if _, err := ask("flooder"); !errors.Is(err, prekey.ErrRateLimited) {
		t.Fatalf("limit not enforced again: %v", err)
	}
	w.now = w.now.Add(time.Hour) // everything expires
	if _, err := ask("flooder"); err != nil {
		t.Fatal("expiry did not free the places:", err)
	}
}

// (h) A disk clone or a restored backup of the target's state directory holds no
// usable keys: the raw private scalars are not in any file, and a daemon
// started from the copy cannot open a frame sealed to the original's live
// prekeys. The scan is checked against a planted key first, so a scan that
// cannot see anything fails the test.
func TestDiskCloneAndBackupHoldNoKeys(t *testing.T) {
	w := newCrashWorld(t)
	var ids [][16]byte
	var wires [][]byte
	for i := 0; i < 4; i++ {
		sp, exp := w.fetch()
		ids = append(ids, sp.ID)
		wires = append(wires, w.seal(sp, sp.PublicKey, newTask(), exp))
	}
	// Run one through so the daemon has written everything it writes.
	if err := w.deliver(wires[0]); err != nil {
		t.Fatal(err)
	}
	w.runs = nil
	live := scalars(t, w.pool, ids[1:]...)

	// Positive control: the scan finds a key that is there.
	probe := t.TempDir()
	if err := os.WriteFile(filepath.Join(probe, "leak"), append([]byte("junk"), live[0]...), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(filesHolding(t, probe, live...)) != 1 {
		t.Fatal("the scan cannot see a planted key")
	}

	if hits := filesHolding(t, w.dir, live...); len(hits) != 0 {
		t.Fatalf("private key bytes on disk: %v", hits)
	}
	if entries, _ := os.ReadDir(w.dir); len(entries) == 0 {
		t.Fatal("the state directory is empty: the daemon wrote nothing, so the scan proves nothing")
	}

	for _, kind := range []string{"clone", "backup"} {
		c := w.onCopyOf(filepath.Join(t.TempDir(), kind))
		if hits := filesHolding(t, c.dir, live...); len(hits) != 0 {
			t.Fatalf("%s: private key bytes on disk: %v", kind, hits)
		}
		for i, wire := range wires[1:] {
			err := c.deliver(wire)
			if !errors.Is(err, receive.ErrDropped) || !errors.Is(err, prekey.ErrUnknown) {
				t.Fatalf("%s opened live prekey %d: %v", kind, i+1, err)
			}
		}
		c.wantRuns(0)
		c.wantState(0, 0, 0)
	}
	// The original is unharmed, and the copy's identity is the real one: it
	// still serves a fresh send.
	if err := w.deliver(wires[1]); err != nil {
		t.Fatal("original after the copies:", err)
	}
	c := w.onCopyOf(filepath.Join(t.TempDir(), "again"))
	if err := c.deliver(c.send(newTask())); err != nil {
		t.Fatal("daemon started from a copy cannot serve:", err)
	}
	c.wantRuns(1)
}

// (i) The restart invariant. Replay safety across a restart relies on prekeys
// being memory only: the replay table is empty after a restart, so the only
// thing stopping a captured frame from running a second time is that the key
// to open it is gone. Checked for a frame that already ran, one that never
// arrived, and one that was held back by the gateway through the restart.
func TestRestartInvariant(t *testing.T) {
	w := newCrashWorld(t)
	ran := w.send(newTask())
	if err := w.deliver(ran); err != nil {
		t.Fatal(err)
	}
	unseen := w.send(newTask())
	w.wantRuns(1)

	w.restart()
	if w.table.Len() != 0 || w.pool.Outstanding() != 0 {
		t.Fatalf("restart kept state: replay=%d keys=%d", w.table.Len(), w.pool.Outstanding())
	}
	for name, wire := range map[string][]byte{"already ran": ran, "never arrived": unseen} {
		for i := 0; i < 3; i++ {
			err := w.deliver(wire)
			if !errors.Is(err, receive.ErrDropped) || !errors.Is(err, prekey.ErrUnknown) {
				t.Fatalf("%s, delivery %d after restart: %v", name, i, err)
			}
		}
	}
	w.wantRuns(1) // still only the first
	w.wantState(0, 0, 1)
	// And a second restart changes nothing.
	w.restart()
	if err := w.deliver(ran); !errors.Is(err, receive.ErrDropped) {
		t.Fatalf("after a second restart: %v", err)
	}
	w.wantRuns(1)
}

// taskTicked reports whether tasks.md marks the task done.
func taskTicked(md, task string) bool {
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "- [x] "+task+" ") {
			return true
		}
	}
	return false
}

func TestTaskTicked(t *testing.T) {
	md := "- [x] T301 Task DO\r\n- [ ] T302 A2A\n  - [x] T3021 sub\n- [x] T30 other\n"
	for task, want := range map[string]bool{"T301": true, "T302": false, "T3021": true, "T30": true, "T999": false} {
		if got := taskTicked(strings.ReplaceAll(md, "\r", ""), task); got != want {
			t.Errorf("taskTicked(%s)=%v want %v", task, got, want)
		}
	}
	if !taskTicked("- [x] T301 Task DO\n", "T301") {
		t.Error("a ticked task is not seen")
	}
}

// pending marks a test that cannot be written until task is built. It skips
// with the reason while the task is open, and FAILS once tasks.md ticks the
// task, so a ticked task cannot leave its acceptance test unwritten.
func pending(t *testing.T, task, reason string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "specs", "parley-mvp", "tasks.md"))
	if err != nil {
		t.Fatal(err)
	}
	if taskTicked(strings.ReplaceAll(string(b), "\r", ""), task) {
		t.Fatalf("%s is ticked but this acceptance test is still pending: write it (%s)", task, reason)
	}
	t.Skipf("pending %s: %s", task, reason)
}

// (f) A five-message follow-up chain erases each key. Follow-ups travel to the
// next-key carried inside the previous message; no shipped code sends or
// receives them yet (the harness's reply path reuses one reply key per task),
// so there is nothing real to assert against.
func TestPending_FollowUpChainErasesEachKey(t *testing.T) {
	pending(t, "T405", "needs the shipped follow-up send/receive path (next-key in inner, INPUT_REQUIRED); assert five messages, each key erased on receipt, each earlier frame unopenable, across a restart")
}

// (g) A late reply after CANCEL is rejected, on both sides of the wire. The
// gateway's shipped Task DO (T301, gateway/src/task.ts) refuses every event after
// CANCEL or FAILED, also after the object restarts; its tests are named below and
// this test fails if they go missing. The device side composes the shipped
// packages (the harness has no shipped reply receiver yet): the reply key is
// erased on CANCEL (confirmed, or unconfirmed at the deadline), on ERROR and at
// expiry, a reply sealed before the cancel is refused when it arrives late, and a
// restart leaves no key at all.
func TestLateReplyAfterCancelIsRejected(t *testing.T) {
	// A task in flight; bob has said he is working, which hands alice his follow-up key.
	// late seals a further reply and holds it back, as a slow gateway would.
	held := func(t *testing.T) (w *world, alice, bob *device, id [16]byte) {
		w = newWorld(t, "alice", "bob")
		alice, bob = w.dev("alice"), w.dev("bob")
		id = start(t, w)
		wantOK(t, bob.reply(id, envelope.TypeStatus, []byte("working")))
		return
	}
	late := func(bob *device, id [16]byte) []byte { return bob.replyWire(id, envelope.TypeResult, []byte("done")) }
	keyGone := func(t *testing.T, alice *device, id [16]byte) {
		t.Helper()
		if o := alice.out[id]; o != nil && o.rsk != nil {
			t.Fatal("the reply key is still held")
		}
	}

	t.Run("after a confirmed CANCEL", func(t *testing.T) {
		w, alice, bob, id := held(t)
		errs, err := alice.cancel(id)
		if err != nil {
			t.Fatal(err)
		}
		wantOK(t, errs)
		wantOK(t, bob.reply(id, envelope.TypeCancel, nil)) // bob confirms: the key goes
		keyGone(t, alice, id)
		wantErr(t, one(t, w.gw.push("alice", late(bob, id))), errNoKey)
		for _, r := range alice.out[id].results {
			if string(r) == "done" {
				t.Fatal("alice took the late reply")
			}
		}
	})

	t.Run("after an unconfirmed CANCEL, once the deadline passes", func(t *testing.T) {
		w, alice, bob, id := held(t)
		lateWire := late(bob, id)
		w.gw.onMsg = func(string, []byte) [][]byte { return nil } // the cancel never arrives
		if _, err := alice.cancel(id); err != nil {
			t.Fatal(err)
		}
		w.gw.onMsg = nil
		if bob.in[id].canceled {
			t.Fatal("bob saw a cancel the gateway dropped")
		}
		// Until the deadline the key is kept, but nothing but a confirmation is taken.
		wantErr(t, one(t, w.gw.push("alice", lateWire)), errAfterCancel)
		w.now = w.now.Add(cancelWait)
		wantErr(t, alice.finishCancel(id), errCancelUnacked)
		keyGone(t, alice, id)
		wantErr(t, one(t, w.gw.push("alice", lateWire)), errNoKey)
	})

	t.Run("after FAILED", func(t *testing.T) {
		w, alice, bob, id := held(t)
		wantOK(t, bob.reply(id, envelope.TypeError, []byte("boom")))
		keyGone(t, alice, id)
		if alice.out[id].state != envelope.TypeError {
			t.Fatalf("state %v", alice.out[id].state)
		}
		wantErr(t, one(t, w.gw.push("alice", late(bob, id))), errNoKey)
		wantErr(t, one(t, bob.reply(id, envelope.TypeResult, []byte("again"))), errNoKey)
	})

	t.Run("after the deadline", func(t *testing.T) {
		w, alice, bob, id := held(t)
		lateWire := late(bob, id)
		w.now = w.now.Add(taskTTL)
		alice.reap(id)
		keyGone(t, alice, id)
		if !alice.out[id].failed {
			t.Fatal("an expired task did not fail")
		}
		// The frame is also past its own signed expiry; either way it is refused and the key stays gone.
		if err := one(t, w.gw.push("alice", lateWire)); err == nil {
			t.Fatal("a reply after the deadline was accepted")
		}
		keyGone(t, alice, id)
	})

	t.Run("after a restart", func(t *testing.T) {
		w, alice, bob, id := held(t)
		lateWire := late(bob, id)
		errs, err := alice.cancel(id)
		if err != nil {
			t.Fatal(err)
		}
		wantOK(t, errs)
		alice.restart() // reply keys live in memory only: nothing survives
		if len(alice.out) != 0 {
			t.Fatal("task state survived the restart")
		}
		wantErr(t, one(t, w.gw.push("alice", lateWire)), errUnknownTask)
		wantErr(t, one(t, bob.reply(id, envelope.TypeResult, []byte("again"))), errUnknownTask)
		snap := alice.snap()
		wantErr(t, one(t, w.gw.push("alice", lateWire)), errUnknownTask)
		snap.unchanged(t)
	})

	t.Run("the gateway's Task DO refuses it too, also after a restart", func(t *testing.T) {
		src, err := os.ReadFile(filepath.Join("..", "..", "gateway", "test", "task.test.ts"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{
			"makes a late reply impossible, also after the object restarts",
			"terminal states are absorbing: nothing moves them",
			"the table is the documented one",
		} {
			if !strings.Contains(string(src), name) {
				t.Errorf("gateway/test/task.test.ts lost the test %q", name)
			}
		}
	})
}

// (e, gateway side) The plan's per-caller rate limit on prekey requests is
// enforced twice: on the device (tested above) and in the Tenant DO.
func TestPending_GatewayRateLimitsPrekeyRequests(t *testing.T) {
	pending(t, "T305", "needs the Tenant DO rate limit; assert a prekey-request flood through the gateway is refused before it reaches the target")
}
