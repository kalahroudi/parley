// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// T206 (spike 3): a malicious-gateway test double and the device logic it
// attacks. The task receive path is the shipped internal/receive code (T204),
// wired to the real prekey pool, replay table, binding tracker and envelope; the
// reply and cancel paths have no shipped receiver yet, so the harness composes
// the same packages for them in the order the plan gives. The gateway can see,
// copy, drop, delay, reorder, rewrite and inject every frame and can answer
// prekey and binding lookups with anything it likes. It holds no key the tenant
// trusts.
//
// Using the harness (T207, T208, T302):
//
//	w := newWorld(t, "alice", "bob")            // devices with root-signed bindings, learned from an honest directory
//	id, errs, err := w.dev("alice").sendTask("bob", content)
//	w.gw.onMsg = func(to string, wire []byte) [][]byte { ... } // drop, duplicate, reorder, rewrite
//	w.gw.onPrekey, w.gw.onBinding = ...         // lie in prekey and directory answers
//	w.gw.push("bob", frames...)                 // inject any bytes, no hook applied
//	mutate(t, wire, func(m *envelope.Message))  // rewrite a captured frame
//	w.dev("bob").restart()                      // crash: fresh pool and replay table, same identity
//	snap := w.dev("bob").snap(); ...; snap.unchanged(t) // junk must change no state
//	w.now = w.now.Add(d); w.dev("bob").skew = d // fake clocks; the harness never sleeps
//
// Determinism: the clock is fake, every key, nonce and task id the harness
// makes comes from one ChaCha8 stream with a fixed seed (harnessSeed), the
// gateway is single-threaded, and nothing sleeps. The only randomness left is
// inside envelope.Seal and prekey.Issue (ephemeral keys), which no assertion
// reads. Failure output carries errors and counts, never keys or message bytes.
//
// The tests are only worth having if they fail without the defences they
// exercise; scripts/malgw-mutations.sh removes each defence in turn and checks
// that the suite goes red. Run it after changing the receive path or the tests.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	mrand "math/rand/v2"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/receive"
	"github.com/kalahroudi/parley/internal/replay"
)

const (
	tenant     = "acme"
	taskTTL    = 15 * time.Minute
	cancelWait = 30 * time.Second
)

// harnessSeed seeds the world's single random stream.
var harnessSeed = [32]byte{'p', 'a', 'r', 'l', 'e', 'y', '-', 'm', 'a', 'l', 'g', 'w', '-', 't', '2', '0', '6'}

var (
	errTimeout        = errors.New("harness: no prekey reply before the timeout")
	errUnknownSender  = errors.New("harness: sender has no verified binding")
	errMisaddressed   = errors.New("harness: message is for another tenant or device")
	errBindingVersion = errors.New("harness: key id or binding version does not match the verified binding")
	errExpired        = errors.New("harness: message past its signed expiry")
	errUnknownTask    = errors.New("harness: no such task")
	errWrongSender    = errors.New("harness: reply is not from the task's target")
	errNoKey          = errors.New("harness: key already erased")
	errOutOfOrder     = errors.New("harness: sequence or previous-message hash does not continue the chain")
	errAfterCancel    = errors.New("harness: reply after cancel")
	errWrongDevice    = errors.New("harness: binding is for another device")
	errCancelUnacked  = errors.New("harness: cancel was not acknowledged")
	errNoNextKey      = errors.New("harness: no follow-up key from the peer yet")
)

func keyID(pub ed25519.PublicKey) string { return hex.EncodeToString(pub[:8]) }

// gateway is the malicious relay. Nil hooks mean honest behavior.
type gateway struct {
	devs map[string]*device
	bind map[string]*binding.Signed

	onBinding func(id string, honest *binding.Signed) *binding.Signed
	// onPrekey sees the honest answer; returning (nil, nil) withholds it.
	onPrekey func(from, to string, honest *prekey.Signed) (*prekey.Signed, error)
	// onMsg decides which frames are delivered for one sent frame, in order.
	onMsg func(to string, wire []byte) [][]byte

	seen map[string][][]byte // every frame sent, by recipient, before tampering
	sent int                 // frames handed to the gateway
}

func (g *gateway) directory(id string) *binding.Signed {
	b := g.bind[id]
	if g.onBinding != nil {
		return g.onBinding(id, b)
	}
	return b
}

func (g *gateway) requestPrekey(from, to string, nonce []byte, taskExpiry time.Time) (*prekey.Signed, error) {
	honest, err := g.devs[to].issue(from, nonce, taskExpiry)
	if err != nil || g.onPrekey == nil {
		return honest, err
	}
	s, err := g.onPrekey(from, to, honest)
	if s == nil && err == nil {
		return nil, errTimeout
	}
	return s, err
}

// deliver relays one frame and returns the receiver's verdict on each frame
// that arrived (none if the gateway dropped it).
func (g *gateway) deliver(to string, wire []byte) []error {
	g.sent++
	g.seen[to] = append(g.seen[to], wire)
	frames := [][]byte{wire}
	if g.onMsg != nil {
		frames = g.onMsg(to, wire)
	}
	return g.push(to, frames...)
}

// push delivers frames as given, with no hook: the gateway injecting traffic.
func (g *gateway) push(to string, frames ...[]byte) []error {
	var errs []error
	for _, f := range frames {
		errs = append(errs, g.devs[to].receive(f))
	}
	return errs
}

type inbound struct {
	caller     string
	rpk        []byte
	expiry     time.Time
	callerSeq  uint64 // next sequence expected from the caller
	callerLast []byte // hash of the last accepted caller message
	sendSeq    uint64
	sendLast   []byte
	nextKeys   map[string][]byte // follow-up private keys, by id; erased on use
	canceled   bool
	content    []byte
}

type outbound struct {
	target   string
	ctx      string
	rsk      []byte // reply private key; nil once erased
	expiry   time.Time
	nextSeq  uint64 // next sequence expected from the target
	last     []byte // hash of the last accepted target message
	sendSeq  uint64
	sent     []byte // hash of the last message we sent
	state    envelope.Type
	failed   bool
	results  [][]byte
	sawAhead bool // a message beyond the next expected one arrived: something was dropped

	peerNext   []byte // the target's follow-up public key; nil once used
	peerNextID string
	canceling  bool
	cancelBy   time.Time
}

type device struct {
	t       *testing.T
	w       *world
	id      string
	sign    ed25519.PrivateKey
	bind    *binding.Signed
	pool    *prekey.Pool
	replays *replay.Table
	tracker *binding.Tracker
	rx      *receive.Receiver // the shipped task receive path
	trusted map[string]*binding.Signed
	in      map[[16]byte]*inbound
	out     map[[16]byte]*outbound
	ran     int // tasks handed to the bot
	acks    int // acknowledgments sent after the key was erased

	skew    time.Duration   // this device's clock minus the world clock
	revoked map[string]bool // senders on the signed revocation list
	denied  map[string]bool // owners the allowlist refuses
}

// now is this device's clock.
func (d *device) now() time.Time { return d.w.now.Add(d.skew) }

type rootKeys struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

type world struct {
	t    *testing.T
	root rootKeys
	now  time.Time
	gw   *gateway
	rng  *mrand.ChaCha8
}

// bytes, edKey and key draw from the world's seeded stream.
func (w *world) bytes(n int) []byte {
	b := make([]byte, n)
	w.rng.Read(b)
	return b
}

func (w *world) edKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(w.bytes(ed25519.SeedSize))
	return priv.Public().(ed25519.PublicKey), priv
}

func (w *world) key() *ecdh.PrivateKey {
	k, err := ecdh.X25519().NewPrivateKey(w.bytes(32))
	if err != nil {
		w.t.Fatal(err)
	}
	return k
}

func newWorld(t *testing.T, ids ...string) *world {
	t.Helper()
	w := &world{t: t, now: t0, rng: mrand.NewChaCha8(harnessSeed)}
	// A bare key pair: root.New stretches a recovery code with PBKDF2, which
	// costs seconds per world under the race detector and adds nothing here.
	rootPub, rootPriv := w.edKey()
	w.root = rootKeys{rootPub, rootPriv}
	w.gw = &gateway{devs: map[string]*device{}, bind: map[string]*binding.Signed{}, seen: map[string][][]byte{}}
	for _, id := range ids {
		pub, priv := w.edKey()
		b := w.approve(id, pub, 1)
		tr, err := binding.NewTracker(rootPub, nil)
		if err != nil {
			t.Fatal(err)
		}
		d := &device{t: t, w: w, id: id, sign: priv, bind: b, tracker: tr, trusted: map[string]*binding.Signed{},
			revoked: map[string]bool{}, denied: map[string]bool{}}
		d.boot()
		t.Cleanup(func() { d.pool.Close() })
		w.gw.devs[id] = d
		w.gw.bind[id] = b
	}
	// Every device learns every other device's binding through an honest directory.
	for _, id := range ids {
		for _, peer := range ids {
			if id != peer {
				if err := w.dev(id).learn(peer); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return w
}

// boot builds the memory-only state of a daemon: prekey pool, replay table,
// task and reply state, and the receiver over them. Identity (signing key,
// binding, trusted peers) is what survives a restart.
func (d *device) boot() {
	d.t.Helper()
	pool, err := prekey.New(prekey.Config{Tenant: tenant, DeviceID: d.id, SigningKeyID: keyID(d.bind.SigningKey), BindingVersion: d.bind.Version,
		Signer: d.sign, AllowUnlocked: true, Now: d.now, SweepEvery: time.Hour})
	if err != nil {
		d.t.Fatal(err)
	}
	d.pool, d.replays = pool, replay.New(replay.Config{Now: d.now})
	d.in, d.out = map[[16]byte]*inbound{}, map[[16]byte]*outbound{}
	d.rx, err = receive.New(receive.Config{Tenant: tenant, Device: d.id, Pool: d.pool, Replay: d.replays, Bindings: d.tracker, Now: d.now,
		Lookup: func(id string) (*binding.Signed, error) {
			if b := d.trusted[id]; b != nil {
				return b, nil
			}
			return nil, errUnknownSender
		},
		Revoked: func(id string) bool { return d.revoked[id] },
		Allow:   func(owner string) bool { return !d.denied[owner] }})
	if err != nil {
		d.t.Fatal(err)
	}
}

// restart models a crash and restart: every prekey private key, the replay
// table and all task state are gone; identity stays.
func (d *device) restart() {
	d.t.Helper()
	d.pool.Close()
	d.boot()
	d.ran, d.acks = 0, 0
}

// state is what a junk frame must not change.
type state struct {
	d           *device
	outstanding int
	replays     int
	ran, acks   int
	tasks       int
}

func (d *device) snap() state {
	return state{d, d.pool.Outstanding(), d.replays.Len(), d.ran, d.acks, len(d.in)}
}

// unchanged fails if the device's prekeys, replay table or task state moved.
func (s state) unchanged(t *testing.T) {
	t.Helper()
	if now := s.d.snap(); now != s {
		t.Fatalf("a refused frame changed state: outstanding %d->%d, replay entries %d->%d, ran %d->%d, acks %d->%d, tasks %d->%d",
			s.outstanding, now.outstanding, s.replays, now.replays, s.ran, now.ran, s.acks, now.acks, s.tasks, now.tasks)
	}
}

func (w *world) approve(id string, pub ed25519.PublicKey, ver uint64) *binding.Signed {
	w.t.Helper()
	b, err := binding.Sign(w.root.Private, binding.Binding{Tenant: tenant, Owner: id + "@acme.test", DeviceID: id,
		SigningKey: pub, Version: ver, NotAfter: w.now.Add(binding.Lifetime)})
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

func (w *world) dev(id string) *device { return w.gw.devs[id] }

// learn fetches a peer's binding through the gateway and trusts it only if the
// pinned root signed it, it is not a rollback, and it is for the device asked.
func (d *device) learn(id string) error {
	b := d.w.gw.directory(id)
	if err := d.tracker.Accept(b, d.now()); err != nil {
		return err
	}
	if b.DeviceID != id {
		return errWrongDevice
	}
	d.trusted[id] = b
	return nil
}

// issue is the target's side of a prekey request: check the caller, then issue.
func (d *device) issue(caller string, nonce []byte, taskExpiry time.Time) (*prekey.Signed, error) {
	if d.trusted[caller] == nil {
		return nil, errUnknownSender
	}
	return d.pool.Issue(prekey.Request{Caller: caller, Nonce: nonce, TaskExpiry: taskExpiry})
}

// fetchPrekey asks the target for a prekey through the gateway and verifies it
// against the target's root-signed binding and this request's nonce.
func (d *device) fetchPrekey(target string, expiry time.Time) (*prekey.Signed, []byte, error) {
	tb := d.trusted[target]
	nonce := d.w.bytes(16)
	s, err := d.w.gw.requestPrekey(d.id, target, nonce, expiry)
	if err != nil {
		return nil, nil, err
	}
	err = prekey.Verify(tb.SigningKey, s, prekey.Expect{Tenant: tenant, DeviceID: target, SigningKeyID: keyID(tb.SigningKey),
		Caller: d.id, Nonce: nonce, BindingVersion: tb.Version, Now: d.now()})
	return s, nonce, err
}

func prekeyBlob(s *prekey.Signed) []byte { return append(s.Encode(), s.Signature...) }

// sealTask seals a task to an already verified prekey, records the outbound
// state and returns the wire frame without sending it.
func (d *device) sealTask(target string, s *prekey.Signed, content []byte) ([16]byte, []byte) {
	d.t.Helper()
	var id [16]byte
	copy(id[:], d.w.bytes(16))
	rsk := d.w.key()
	expiry := d.now().Add(taskTTL)
	h := envelope.Header{Tenant: tenant, SenderDevice: d.id, SenderKeyID: keyID(d.bind.SigningKey), BindingVersion: d.bind.Version,
		TargetDevice: target, PrekeyID: hex.EncodeToString(s.ID[:]), TaskID: id, ContextID: "ctx-" + hex.EncodeToString(id[:4]),
		Seq: 0, Type: envelope.TypeTask, IssuedAt: d.now(), Expiry: expiry, RPK: rsk.PublicKey().Bytes(), Prekey: prekeyBlob(s)}
	m, err := envelope.Seal(d.sign, s.PublicKey, h, content)
	if err != nil {
		d.t.Fatal(err)
	}
	hh := h.Hash()
	d.out[id] = &outbound{target: target, ctx: h.ContextID, rsk: rsk.Bytes(), expiry: expiry, nextSeq: 1, last: hh[:], sent: hh[:], state: envelope.TypeTask}
	return id, m.Marshal()
}

// sendTask is the honest caller flow: fetch, verify, seal, send.
func (d *device) sendTask(target string, content []byte) ([16]byte, []error, error) {
	s, _, err := d.fetchPrekey(target, d.now().Add(taskTTL))
	if err != nil {
		return [16]byte{}, nil, err
	}
	id, wire := d.sealTask(target, s, content)
	return id, d.w.gw.deliver(target, wire), nil
}

// receive dispatches a frame. The header type is only a routing hint: each path
// verifies everything it relies on.
func (d *device) receive(wire []byte) error {
	m, err := envelope.Unmarshal(wire)
	if err != nil {
		return err
	}
	// CANCEL travels both ways (the target's acknowledgment is one too), so it
	// is a request only where this device is the task's target.
	if m.Header.Type == envelope.TypeTask || (m.Header.Type == envelope.TypeCancel && d.in[m.Header.TaskID] != nil) {
		return d.recvRequest(m)
	}
	return d.recvReply(m)
}

// checkCommon holds the header checks shared by both directions.
func (d *device) checkCommon(m *envelope.Message) (*binding.Signed, error) {
	h := m.Header
	sb := d.trusted[h.SenderDevice]
	if sb == nil {
		return nil, errUnknownSender
	}
	if h.Tenant != tenant || h.TargetDevice != d.id {
		return nil, errMisaddressed
	}
	if h.BindingVersion != sb.Version || h.SenderKeyID != keyID(sb.SigningKey) {
		return nil, errBindingVersion
	}
	if !d.now().Before(h.Expiry) {
		return nil, errExpired
	}
	return sb, nil
}

// recvRequest hands a task to the shipped receive path (open, verify, record,
// erase, ack, execute); a cancel travels to a follow-up key, which the harness
// handles itself.
func (d *device) recvRequest(m *envelope.Message) error {
	if m.Header.Type == envelope.TypeCancel {
		sb, err := d.checkCommon(m)
		if err != nil {
			return err
		}
		return d.recvCancel(m, sb)
	}
	return d.rx.Receive(m, func() error { d.acks++; return nil }, func(dl receive.Delivered) error {
		h := dl.Header
		hh := h.Hash()
		d.in[h.TaskID] = &inbound{caller: h.SenderDevice, rpk: h.RPK, expiry: h.Expiry, callerSeq: 1, callerLast: hh[:],
			nextKeys: map[string][]byte{}, content: append([]byte(nil), dl.Plaintext...)}
		d.ran++
		return nil
	})
}

func (d *device) recvCancel(m *envelope.Message, sb *binding.Signed) error {
	h := m.Header
	in := d.in[h.TaskID]
	if in == nil {
		return errUnknownTask
	}
	if h.SenderDevice != in.caller {
		return errWrongSender
	}
	sk := in.nextKeys[h.PrekeyID]
	if sk == nil {
		return errNoKey
	}
	if _, err := m.Open(sk); err != nil {
		return err
	}
	if err := m.Verify(sb.SigningKey); err != nil {
		return err
	}
	if h.Seq != in.callerSeq || !bytes.Equal(h.PrevHash, in.callerLast) {
		return errOutOfOrder
	}
	if err := d.replays.Accept(replay.Key{Sender: h.SenderDevice, Task: h.TaskID, Seq: h.Seq}, h.Expiry); err != nil {
		return err
	}
	clear(sk)
	delete(in.nextKeys, h.PrekeyID)
	hh := h.Hash()
	in.callerSeq, in.callerLast, in.canceled = h.Seq+1, hh[:], true
	return nil
}

// reply sends a message toward the caller's reply key. It carries a fresh
// follow-up key inside the ciphertext, as the plan requires. It does not check
// for cancel: a bot may well be mid-reply when the cancel arrives.
func (d *device) reply(id [16]byte, typ envelope.Type, content []byte) []error {
	return d.w.gw.deliver(d.in[id].caller, d.replyWire(id, typ, content))
}

// replyWire seals a reply and returns it unsent, for the gateway to hold,
// reorder or tamper with.
func (d *device) replyWire(id [16]byte, typ envelope.Type, content []byte) []byte {
	d.t.Helper()
	in := d.in[id]
	nk := d.w.key()
	nkID := keyID(nk.PublicKey().Bytes())
	in.nextKeys[nkID] = nk.Bytes()
	in.sendSeq++
	h := envelope.Header{Tenant: tenant, SenderDevice: d.id, SenderKeyID: keyID(d.bind.SigningKey), BindingVersion: d.bind.Version,
		TargetDevice: in.caller, PrekeyID: "rpk", TaskID: id, ContextID: "ctx", Seq: in.sendSeq, Type: typ,
		IssuedAt: d.now(), Expiry: in.expiry, PrevHash: in.sendLast}
	if in.sendSeq == 1 {
		h.PrevHash = in.callerLast // first reply chains to the task
	}
	m, err := envelope.Seal(d.sign, in.rpk, h, append(nk.PublicKey().Bytes(), content...))
	if err != nil {
		d.t.Fatal(err)
	}
	hh := h.Hash()
	in.sendLast = hh[:]
	return m.Marshal()
}

func (d *device) recvReply(m *envelope.Message) error {
	h := m.Header
	sb, err := d.checkCommon(m)
	if err != nil {
		return err
	}
	out := d.out[h.TaskID]
	if out == nil {
		return errUnknownTask
	}
	if h.SenderDevice != out.target {
		return errWrongSender
	}
	if out.rsk == nil {
		return errNoKey
	}
	pt, err := m.Open(out.rsk)
	if err != nil {
		return err
	}
	if err := m.Verify(sb.SigningKey); err != nil {
		return err
	}
	if out.canceling && h.Type != envelope.TypeCancel {
		return errAfterCancel
	}
	key := replay.Key{Sender: h.SenderDevice, Task: h.TaskID, Seq: h.Seq}
	if h.Seq < out.nextSeq {
		if err := d.replays.Accept(key, h.Expiry); err != nil {
			return err
		}
		return errOutOfOrder
	}
	if h.Seq > out.nextSeq {
		out.sawAhead = true
		return errOutOfOrder
	}
	if !bytes.Equal(h.PrevHash, out.last) {
		return errOutOfOrder
	}
	if err := d.replays.Accept(key, h.Expiry); err != nil {
		return err
	}
	hh := h.Hash()
	out.nextSeq, out.last, out.state = h.Seq+1, hh[:], h.Type // the signed type is the authoritative state
	out.peerNext, out.peerNextID = pt[:32], keyID(pt[:32])
	out.results = append(out.results, pt[32:])
	if h.Type == envelope.TypeResult || h.Type == envelope.TypeError || h.Type == envelope.TypeCancel {
		d.erase(out)
	}
	return nil
}

func (d *device) erase(o *outbound) {
	clear(o.rsk)
	o.rsk = nil
}

// cancel sends CANCEL to the follow-up key from the target's last reply. The
// reply key stays until the target acknowledges or cancelWait passes, so the
// acknowledgment can be read; anything else arriving in between is refused.
func (d *device) cancel(id [16]byte) ([]error, error) {
	o := d.out[id]
	if o.peerNext == nil {
		return nil, errNoNextKey
	}
	o.sendSeq++
	h := envelope.Header{Tenant: tenant, SenderDevice: d.id, SenderKeyID: keyID(d.bind.SigningKey), BindingVersion: d.bind.Version,
		TargetDevice: o.target, PrekeyID: o.peerNextID, TaskID: id, ContextID: o.ctx, Seq: o.sendSeq, Type: envelope.TypeCancel,
		IssuedAt: d.now(), Expiry: o.expiry, PrevHash: o.sent}
	m, err := envelope.Seal(d.sign, o.peerNext, h, nil)
	if err != nil {
		d.t.Fatal(err)
	}
	o.peerNext = nil
	o.canceling, o.cancelBy = true, d.now().Add(cancelWait)
	hh := h.Hash()
	o.sent = hh[:]
	return d.w.gw.deliver(o.target, m.Marshal()), nil
}

// finishCancel erases the reply key once the cancel deadline passes, and says
// whether the target ever confirmed.
func (d *device) finishCancel(id [16]byte) error {
	o := d.out[id]
	if o.state == envelope.TypeCancel {
		return nil
	}
	if d.now().Before(o.cancelBy) {
		return errTimeout
	}
	d.erase(o)
	o.failed = true
	return errCancelUnacked
}

// reap fails a task with no final message by its expiry and erases its key.
func (d *device) reap(id [16]byte) {
	o := d.out[id]
	if !d.now().Before(o.expiry) && o.rsk != nil {
		d.erase(o)
		o.failed = true
	}
}

// mutate rewrites a wire frame the way a gateway could.
func mutate(t *testing.T, wire []byte, f func(m *envelope.Message)) []byte {
	t.Helper()
	m, err := envelope.Unmarshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	f(m)
	return m.Marshal()
}
