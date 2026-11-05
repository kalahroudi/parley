// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/frames"
	"github.com/kalahroudi/parley/internal/outbox"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/receive"
	"github.com/kalahroudi/parley/internal/replay"
	"github.com/kalahroudi/parley/internal/revocation"
)

// list installs a newer revocation list on a device, as a refresh would.
func (w *world) list(d *dev, version uint64, issued time.Time, revoked ...string) {
	w.t.Helper()
	s, err := revocation.Sign(w.root, revocation.List{Tenant: tenant, Version: version, IssuedAt: issued, Revoked: revoked})
	if err != nil {
		w.t.Fatal(err)
	}
	if err := d.node.cfg.Trust.Guard.Accept(s, w.clock()); err != nil {
		w.t.Fatal(err)
	}
}

// forge is what a rogue but enrolled device can do: seal any payload to a key
// the target really issued to it, with a valid signature and binding.
type forged struct {
	wire []byte
	rpk  *prekey.Signed
	h    envelope.Header
}

func (w *world) forgeTask(from, to *dev, inner func(rpk *prekey.Signed) []byte, pad bool) forged {
	w.t.Helper()
	return w.forgeTaskAs(from, to, nil, inner, pad)
}

// forgeTaskWith seals a well-formed padded TASK whose reply key is the given one.
func (w *world) forgeTaskWith(from, to *dev, rpk *prekey.Signed, inner func(rpk *prekey.Signed) []byte) forged {
	w.t.Helper()
	return w.forgeTaskAs(from, to, rpk, inner, true)
}

func (w *world) forgeTaskAs(from, to *dev, given *prekey.Signed, inner func(rpk *prekey.Signed) []byte, pad bool) forged {
	w.t.Helper()
	exp := w.clock().Add(15 * time.Minute)
	sp, err := to.pool.Issue(prekey.Request{Caller: from.id, Nonce: []byte("0123456789abcdef"), TaskExpiry: exp})
	if err != nil {
		w.t.Fatal(err)
	}
	rpk := given
	if rpk == nil {
		var err error
		if rpk, err = from.pool.Issue(prekey.Request{Caller: to.id, Nonce: []byte("fedcba9876543210"), TaskExpiry: exp}); err != nil {
			w.t.Fatal(err)
		}
	}
	var id [16]byte
	_, _ = rand.Read(id[:])
	h := envelope.Header{Tenant: tenant, SenderDevice: from.id, SenderKeyID: KeyID(from.sign.Public().(ed25519.PublicKey)), BindingVersion: 1,
		TargetDevice: to.id, PrekeyID: receive.PrekeyID(sp.ID), TaskID: id, ContextID: "c", Type: envelope.TypeTask, IssuedAt: w.clock(), Expiry: exp,
		RPK: rpk.PublicKey, Prekey: frames.EncodePrekey(sp)}
	body := inner(rpk)
	var m *envelope.Message
	if pad {
		m, err = envelope.SealPadded(from.sign, sp.PublicKey, h, body)
	} else {
		m, err = envelope.Seal(from.sign, sp.PublicKey, h, body)
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return forged{wire: m.Marshal(), rpk: rpk, h: h}
}

func (w *world) feed(d *dev, wire []byte) error {
	w.t.Helper()
	return d.node.HandleEvent(bg, tunnelEvent(event(wire)))
}

func TestNewRefusesIncompleteConfig(t *testing.T) {
	w := newWorld(t, "alice")
	good := w.devs["alice"].node.cfg
	cases := map[string]func(*Config){
		"tenant": func(c *Config) { c.Tenant = "" }, "device": func(c *Config) { c.Device = "" }, "signer": func(c *Config) { c.Signer = nil },
		"version": func(c *Config) { c.Version = 0 }, "pool": func(c *Config) { c.Pool = nil }, "replay": func(c *Config) { c.Replay = nil },
		"trust": func(c *Config) { c.Trust = nil }, "directory": func(c *Config) { c.Directory = nil }, "allow": func(c *Config) { c.Allow = nil },
		"relay": func(c *Config) { c.Relay = nil }, "gateway": func(c *Config) { c.Gateway = nil }, "inbound": func(c *Config) { c.OnInbound = nil },
		"update": func(c *Config) { c.OnUpdate = nil },
	}
	for name, mod := range cases {
		c := good
		mod(&c)
		if _, err := New(c); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v, want ErrConfig", name, err)
		}
	}
	c := good
	tr := *c.Trust
	tr.Tracker = nil
	c.Trust = &tr
	if _, err := New(c); !errors.Is(err, receive.ErrConfig) {
		t.Errorf("a trust daemon without a tracker: %v", err)
	}
	c = good
	c.MaxTasks, c.MaxPeers, c.MaxPending, c.RequestTimeout, c.CancelWait, c.Now, c.Rand = 7, 7, 7, time.Second, time.Second, nil, nil
	n, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	n.Close()
	if n.cfg.MaxTasks != 7 || n.cfg.RequestTimeout != time.Second || n.cfg.Now == nil || n.cfg.Rand == nil {
		t.Fatalf("%+v", n.cfg)
	}
}

func TestSubmitRefusesBadRequests(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	a := w.devs["alice"].node
	exp := w.clock().Add(time.Minute)
	for name, r := range map[string]Request{
		"no target": {Content: []byte("x"), Expiry: exp}, "bad target": {Target: "a b", Content: []byte("x"), Expiry: exp},
		"too big": {Target: "bob", Content: make([]byte, MaxContent+1), Expiry: exp},
	} {
		if _, err := a.Submit(r); !errors.Is(err, outbox.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := a.Submit(Request{Target: "bob", Content: []byte("x"), Expiry: w.clock().Add(-time.Second)}); !errors.Is(err, outbox.ErrExpired) {
		t.Errorf("expired: %v", err)
	}
	if len(a.queue) != 0 {
		t.Fatal("a refused request left its content in memory")
	}
	// The queue is bounded.
	a.cfg.MaxPending = 1
	w.devs["bob"].online.Store(false)
	id, err := a.Submit(Request{Target: "bob", Content: []byte("x"), Expiry: exp})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Submit(Request{Target: "bob", Content: []byte("y"), Expiry: exp}); !errors.Is(err, ErrBusy) {
		t.Errorf("queue full: %v", err)
	}
	// Abandoning drops the content at once.
	eventually(t, "the task to be waiting or sending", func() bool { _, ok := a.Status(id); return ok })
	for i := 0; i < 500; i++ {
		if err := a.Abandon(id); err == nil {
			break
		} else if !errors.Is(err, outbox.ErrSending) {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	eventually(t, "the content to be dropped", func() bool { a.mu.Lock(); defer a.mu.Unlock(); return len(a.queue) == 0 })
	if err := a.Abandon([16]byte{1}); !errors.Is(err, outbox.ErrUnknown) {
		t.Errorf("abandon unknown: %v", err)
	}
}

func TestSendRefusesWhileTrustStateIsNotGood(t *testing.T) {
	cases := map[string]struct {
		setup func(w *world)
		want  error
	}{
		"not enrolled at the version the pool carries": {func(w *world) { w.devs["alice"].node.cfg.Version = 2 }, ErrNotReady},
		"this device is revoked":                       {func(w *world) { w.list(w.devs["alice"], 2, w.clock(), "alice") }, revocation.ErrRevoked},
		"the recipient is revoked":                     {func(w *world) { w.list(w.devs["alice"], 2, w.clock(), "bob") }, revocation.ErrRevoked},
		"the revocation list is too old":               {func(w *world) { w.advance(15 * 24 * time.Hour) }, revocation.ErrStale},
		"the recipient's binding expired":              {func(w *world) { w.advance(binding.Lifetime + time.Hour); w.list(w.devs["alice"], 2, w.clock()) }, binding.ErrExpired},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, "alice", "bob")
			c.setup(w)
			_, st := w.send("alice", "bob", "x")
			if st.State != outbox.Failed || !errors.Is(st.Err, c.want) {
				t.Fatalf("%+v, want %v", st, c.want)
			}
			if len(w.sent) != 0 || len(w.relayed) != 0 {
				t.Fatalf("something went on the wire: %d messages, %d frames", len(w.sent), len(w.relayed))
			}
			if w.devs["alice"].pool.Outstanding() != 0 {
				t.Fatal("a key was generated before the checks passed")
			}
		})
	}
}

func TestSendToAnUnknownOrUnreachableDirectory(t *testing.T) {
	w := newWorld(t, "alice")
	_, st := w.send("alice", "nobody", "x")
	if st.State != outbox.Failed || !errors.Is(st.Err, outbox.ErrGone) {
		t.Fatalf("%+v", st)
	}
	// A directory that cannot be asked is waited out, not treated as "gone".
	a := w.devs["alice"].node
	a.cfg.Directory = func(context.Context, string) (*binding.Signed, error) { return nil, errors.New("down") }
	id, err := a.Submit(Request{Target: "bob", Content: []byte("x"), Expiry: w.clock().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if st, _ := a.Status(id); st.State == outbox.Failed || st.State == outbox.Sent {
		t.Fatalf("%+v", st)
	}
	for a.Abandon(id) != nil { // wait until it is between attempts
		time.Sleep(time.Millisecond)
	}
	<-a.Done(id)
	// A directory that answers with another device's binding is not believed.
	w.add("bob")
	a.cfg.Directory = func(context.Context, string) (*binding.Signed, error) { return w.devs["alice"].bind, nil }
	if _, err := a.peer(bg, "bob", 0); !errors.Is(err, ErrPeer) {
		t.Fatal(err)
	}
	a.cfg.Directory = func(context.Context, string) (*binding.Signed, error) { return nil, nil }
	if _, err := a.peer(bg, "bob", 0); !errors.Is(err, ErrPeer) {
		t.Fatal(err)
	}
}

func TestPeerCacheIsBoundedAndRefetchesOnAVersionChange(t *testing.T) {
	w := newWorld(t, "alice", "bob", "carol")
	a := w.devs["alice"].node
	a.cfg.MaxPeers = 1
	calls := 0
	a.cfg.Directory = func(_ context.Context, d string) (*binding.Signed, error) { calls++; return w.devs[d].bind, nil }
	for _, d := range []string{"bob", "carol", "bob", "bob"} {
		if _, err := a.peer(bg, d, 0); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.peers) != 1 || calls != 3 {
		t.Fatalf("peers=%d lookups=%d, want 1 and 3", len(a.peers), calls)
	}
	if _, err := a.peer(bg, "bob", 2); err != nil || calls != 4 {
		t.Fatalf("a message naming another binding version must ask the directory again: %v lookups=%d", err, calls)
	}
}

func TestSealedMessageFromAnUnknownSenderIsRefused(t *testing.T) {
	w := newWorld(t, "alice", "bob", "mallory")
	f := w.forgeTask(w.devs["mallory"], w.devs["bob"], func(rpk *prekey.Signed) []byte { return frames.PackInner(rpk, []byte("x")) }, true)
	delete(w.devs, "mallory") // the directory no longer knows it
	if err := w.feed(w.devs["bob"], f.wire); !errors.Is(err, ErrPeer) {
		t.Fatalf("%v", err)
	}
	if w.devs["bob"].pool.Outstanding() != 1 || w.devs["bob"].table.Len() != 0 {
		t.Fatal("a message from an unknown sender changed state")
	}
}

func TestPrekeyRequestFromRevokedOrOwnDeviceIsRefused(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	bob := w.devs["bob"]
	var out []string
	bob.node.cfg.Relay = func(b string) error { out = append(out, b); return nil }
	r := &frames.Relay{Kind: frames.KindPrekeyRequest, ID: "r", Peer: "bob", Nonce: []byte("0123456789abcdef"), TaskExpiry: w.clock().Add(time.Minute)}
	if err := bob.node.servePrekey(bg, r); !errors.Is(err, ErrPeer) {
		t.Fatalf("own device: %v", err)
	}
	w.list(bob, 2, w.clock(), "alice")
	r.Peer = "alice"
	if err := bob.node.servePrekey(bg, r); !errors.Is(err, ErrPeer) || bob.pool.Outstanding() != 0 {
		t.Fatalf("revoked: %v", err)
	}
	for _, o := range out {
		if !strings.Contains(o, "prekey_refused") {
			t.Fatalf("answered with %s", o)
		}
	}
	// A binding the tracker refuses (older than one seen) is refused too.
	w2 := newWorld(t, "alice", "bob")
	b2 := w2.devs["bob"]
	b2.node.cfg.Relay = func(string) error { return nil }
	newer, _ := binding.Sign(w2.root, binding.Binding{Tenant: tenant, Owner: "alice@acme.test", DeviceID: "alice", SigningKey: w2.devs["alice"].bind.SigningKey, Version: 5, NotAfter: t0.Add(binding.Lifetime)})
	if err := b2.node.cfg.Trust.Tracker.Accept(newer, t0); err != nil {
		t.Fatal(err)
	}
	r2 := &frames.Relay{Kind: frames.KindPrekeyRequest, ID: "r", Peer: "alice", Nonce: []byte("0123456789abcdef"), TaskExpiry: w2.clock().Add(time.Minute)}
	if err := b2.node.servePrekey(bg, r2); !errors.Is(err, ErrPeer) {
		t.Fatalf("rolled-back binding: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestNoRandomnessIsFatal(t *testing.T) {
	w := newWorld(t, "alice")
	n := w.devs["alice"].node
	n.cfg.Rand = failingReader{}
	defer func() {
		if recover() == nil {
			t.Fatal("a key or id made without randomness")
		}
	}()
	_, _ = n.Submit(Request{Target: "bob", Content: []byte("x"), Expiry: w.clock().Add(time.Minute)})
}

// A rogue but enrolled device can seal anything it likes. Each malformed TASK
// is dropped after the key is spent (the sender is authenticated and answers
// for it), creates no task, and never reaches the bot.
func TestMalformedTaskPayloadsNeverReachTheBot(t *testing.T) {
	good := func(rpk *prekey.Signed) []byte { return frames.PackInner(rpk, []byte("x")) }
	other := func(rpk *prekey.Signed) []byte {
		w := newWorld(t, "o")
		k, _ := w.devs["o"].pool.Issue(prekey.Request{Caller: "bob", Nonce: []byte("n"), TaskExpiry: t0.Add(time.Minute)})
		return frames.PackInner(k, []byte("x"))
	}
	cases := map[string]struct {
		inner func(*prekey.Signed) []byte
		pad   bool
	}{
		"not padded":               {good, false},
		"padded but not a payload": {func(*prekey.Signed) []byte { return []byte{9, 9, 9} }, true},
		"no reply key":             {func(*prekey.Signed) []byte { return frames.PackInner(nil, []byte("x")) }, true},
		"a key that is not the header's rpk": {func(rpk *prekey.Signed) []byte {
			c := *rpk
			c.PublicKey = bytes.Repeat([]byte{7}, 32)
			return frames.PackInner(&c, []byte("x"))
		}, true},
		"a reply key signed by someone else": {other, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, "alice", "bob", "mallory")
			f := w.forgeTask(w.devs["mallory"], w.devs["bob"], c.inner, c.pad)
			if err := w.feed(w.devs["bob"], f.wire); err == nil {
				t.Fatal("accepted")
			}
			if w.devs["bob"].inboxLen() != 0 || len(w.devs["bob"].node.chains) != 0 {
				t.Fatal("the bot or the task table saw a malformed task")
			}
		})
	}
	// And the same wire, well formed, is accepted: the cases above fail for their own reason.
	w := newWorld(t, "alice", "bob", "mallory")
	f := w.forgeTask(w.devs["mallory"], w.devs["bob"], good, true)
	if err := w.feed(w.devs["bob"], f.wire); err != nil || w.devs["bob"].inboxLen() != 1 {
		t.Fatalf("%v", err)
	}
	// The pipeline refuses a second task while the table is full, before spending its key.
	w.devs["bob"].node.cfg.MaxTasks = 1
	f2 := w.forgeTask(w.devs["alice"], w.devs["bob"], good, true)
	before := w.devs["bob"].pool.Outstanding()
	if err := w.feed(w.devs["bob"], f2.wire); !errors.Is(err, receive.ErrRejected) || w.devs["bob"].pool.Outstanding() != before {
		t.Fatalf("%v", err)
	}
	// A duplicate task id is refused likewise.
	w.devs["bob"].node.cfg.MaxTasks = 10
	f3 := w.forgeTask(w.devs["mallory"], w.devs["bob"], good, true)
	w.devs["bob"].node.chains[f3.h.TaskID] = &chain{role: target}
	if err := w.feed(w.devs["bob"], f3.wire); !errors.Is(err, receive.ErrRejected) {
		t.Fatalf("%v", err)
	}
}

// A rogue target answers with payloads the caller cannot use.
func TestMalformedRepliesAreNotAccepted(t *testing.T) {
	cases := map[string]struct {
		typ   envelope.Type
		inner func(chain *chain, w *world) []byte
		pad   bool
	}{
		"not padded":                          {envelope.TypeStatus, func(*chain, *world) []byte { return frames.PackInner(nil, nil) }, false},
		"not a payload":                       {envelope.TypeStatus, func(*chain, *world) []byte { return []byte{9} }, true},
		"a question with no key to answer it": {envelope.TypeInputRequired, func(*chain, *world) []byte { return frames.PackInner(nil, []byte("q")) }, true},
		"a key that does not verify": {envelope.TypeStatus, func(_ *chain, w *world) []byte {
			k, _ := w.devs["alice"].pool.Issue(prekey.Request{Caller: "bob", Nonce: []byte("n"), TaskExpiry: t0.Add(time.Minute)})
			return frames.PackInner(k, nil)
		}, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, "alice", "bob")
			id := w.run("alice", "bob", "x")
			alice, bob := w.devs["alice"], w.devs["bob"]
			ch := alice.node.chains[id]
			h := envelope.Header{Tenant: tenant, SenderDevice: "bob", SenderKeyID: KeyID(bob.sign.Public().(ed25519.PublicKey)), BindingVersion: 1, TargetDevice: "alice",
				PrekeyID: receive.PrekeyID(ch.reply.ID), TaskID: id, ContextID: ch.context, Seq: 1, Type: c.typ, IssuedAt: w.clock(), Expiry: w.clock().Add(15 * time.Minute), PrevHash: ch.recvLast}
			body := c.inner(ch, w)
			var m *envelope.Message
			var err error
			if c.pad {
				m, err = envelope.SealPadded(bob.sign, ch.reply.PublicKey, h, body)
			} else {
				m, err = envelope.Seal(bob.sign, ch.reply.PublicKey, h, body)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := w.feed(alice, m.Marshal()); err == nil {
				t.Fatal("accepted")
			}
			if alice.updateLen() != 0 {
				t.Fatal("the caller was told about a malformed reply")
			}
		})
	}
}

// A caller's follow-up must not carry a key; a second question before an answer is refused.
func TestFollowUpShapeIsChecked(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	if err := bob.node.Respond(bg, id, envelope.TypeInputRequired, []byte("q?")); err != nil {
		t.Fatal(err)
	}
	w.settle()
	ch := bob.node.chains[id]
	k, _ := alice.pool.Issue(prekey.Request{Caller: "bob", Nonce: []byte("n"), TaskExpiry: t0.Add(time.Minute)})
	h := envelope.Header{Tenant: tenant, SenderDevice: "alice", SenderKeyID: KeyID(alice.sign.Public().(ed25519.PublicKey)), BindingVersion: 1, TargetDevice: "bob",
		PrekeyID: receive.PrekeyID(ch.follow.ID), TaskID: id, ContextID: ch.context, Seq: 1, Type: envelope.TypeReply, IssuedAt: w.clock(), Expiry: w.clock().Add(15 * time.Minute), PrevHash: ch.recvLast}
	m, err := envelope.SealPadded(alice.sign, ch.follow.PublicKey, h, frames.PackInner(k, []byte("a")))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.feed(bob, m.Marshal()); !errors.Is(err, ErrInner) {
		t.Fatalf("a follow-up carrying a key: %v", err)
	}
	// A second question while the first is unanswered (the caller side refuses it).
	if err := bob.node.Respond(bg, id, envelope.TypeInputRequired, []byte("q2?")); err != nil {
		t.Fatal(err)
	}
	w.settle()
	if err := alice.lastErr(); !errors.Is(err, receive.ErrRejected) {
		t.Fatalf("second question: %v", err)
	}
}

func TestRespondAndFollowFailuresLeaveTheKeysAlone(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	_ = bob.node.Respond(bg, id, envelope.TypeStatus, []byte("w"))
	w.settle()
	keys := func() (int, int) { return alice.pool.Outstanding(), bob.pool.Outstanding() }
	a0, b0 := keys()

	// The gateway refuses a reply: the old follow-up key stays the only live one.
	w.gw("bob").setFail(errors.New("down"))
	if err := bob.node.Respond(bg, id, envelope.TypeStatus, []byte("again")); err == nil {
		t.Fatal("sent through a failing gateway")
	}
	w.gw("bob").setFail(nil)
	if a, b := keys(); a != a0 || b != b0 {
		t.Fatalf("keys changed by a failed reply: %d/%d -> %d/%d", a0, b0, a, b)
	}
	// A revoked caller gets no reply.
	w.list(bob, 2, w.clock(), "alice")
	if err := bob.node.Respond(bg, id, envelope.TypeStatus, nil); !errors.Is(err, revocation.ErrRevoked) {
		t.Fatalf("%v", err)
	}
	if a, b := keys(); a != a0 || b != b0 {
		t.Fatal("keys changed")
	}
	// A revoked target gets no follow-up, and the follow-up key is not spent by the refusal.
	w.list(alice, 2, w.clock(), "bob")
	if err := alice.node.Follow(bg, id, envelope.TypeCancel, nil); !errors.Is(err, revocation.ErrRevoked) {
		t.Fatalf("%v", err)
	}
	if alice.node.chains[id].follow == nil || alice.node.chains[id].busy || bob.node.chains[id].busy {
		t.Fatal("a refused follow-up spent the key or left the chain busy")
	}
	// The pool is gone: no new follow-up key can be made.
	bob.pool.Close()
	w.list(bob, 3, w.clock())
	if err := bob.node.Respond(bg, id, envelope.TypeStatus, nil); err == nil {
		t.Fatal("replied with no key to offer")
	}
	// Not enrolled at the pool's version.
	bob.node.cfg.Version = 9
	if err := bob.node.Respond(bg, id, envelope.TypeResult, nil); !errors.Is(err, ErrNotReady) {
		t.Fatal(err)
	}
	alice.node.cfg.Version = 9
	if err := alice.node.Follow(bg, id, envelope.TypeCancel, nil); !errors.Is(err, ErrNotReady) {
		t.Fatal(err)
	}
}

func TestOneMessageAtATimePerTask(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	bob := w.devs["bob"]
	id := w.run("alice", "bob", "x")
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	real := w.gw("bob")
	bob.node.cfg.Gateway = gatewayFunc(func(ctx context.Context, m Outgoing) error {
		started <- struct{}{}
		<-release
		return real.route(m)
	})
	done := make(chan error, 1)
	go func() { done <- bob.node.Respond(bg, id, envelope.TypeStatus, []byte("one")) }()
	<-started
	if err := bob.node.Respond(bg, id, envelope.TypeStatus, []byte("two")); !errors.Is(err, ErrState) {
		t.Fatalf("a second message while one is in flight: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	w.settle()
	if got := bob.node.chains[id].sendSeq; got != 1 {
		t.Fatalf("sequence %d", got)
	}
}

type gatewayFunc func(ctx context.Context, m Outgoing) error

func (f gatewayFunc) Send(ctx context.Context, m Outgoing) error   { return f(ctx, m) }
func (f gatewayFunc) Cancel(ctx context.Context, m Outgoing) error { return f(ctx, m) }

func TestWaitingTableIsBounded(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	a := w.devs["alice"].node
	a.cfg.MaxPending = 1
	a.waiting["x"] = &waiter{}
	_, err := a.requestPrekey(bg, w.devs["bob"].bind, w.clock().Add(time.Minute))
	if !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, err := a.requestPrekey(bg, &binding.Signed{Binding: binding.Binding{DeviceID: "a b"}}, w.clock().Add(time.Minute)); err == nil {
		t.Fatal("asked a device that cannot exist")
	}
}

func TestCloseErasesEverything(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.run("alice", "bob", "x")
	w.devs["alice"].node.Close()
	w.devs["bob"].node.Close()
	if w.devs["alice"].pool.Outstanding() != 0 || w.devs["bob"].pool.Outstanding() != 0 {
		t.Fatal("keys survived Close")
	}
	if len(w.devs["alice"].node.chains) != 0 || len(w.devs["bob"].node.chains) != 0 {
		t.Fatal("tasks survived Close")
	}
	if _, err := w.devs["alice"].node.Submit(Request{Target: "bob", Content: []byte("x"), Expiry: w.clock().Add(time.Minute)}); err == nil {
		t.Fatal("submitted after Close")
	}
}

var _ = replay.ErrReplay

// A reply that arrives while a follow-up is being sealed brings a newer key and erases the older one at the
// target: the follow-up is not sent, and the newer key is not lost.
func TestFollowUpLosesTheRaceToANewerReply(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	alice, bob := w.devs["alice"], w.devs["bob"]
	id := w.run("alice", "bob", "x")
	_ = bob.node.Respond(bg, id, envelope.TypeStatus, []byte("one"))
	w.settle()
	a := alice.node
	old := a.chains[id].follow
	sent := len(w.sent)
	// The directory is asked (the cache is empty) between taking the key and sealing: a second reply lands there.
	a.mu.Lock()
	clear(a.peers)
	a.mu.Unlock()
	var once atomic.Bool
	a.cfg.Directory = func(_ context.Context, d string) (*binding.Signed, error) {
		if once.CompareAndSwap(false, true) {
			if err := bob.node.Respond(bg, id, envelope.TypeStatus, []byte("two")); err != nil {
				t.Error(err)
			}
			eventually(t, "the second reply to be processed", func() bool { return alice.updateLen() == 2 })
		}
		return w.devs[d].bind, nil
	}
	if err := a.Follow(bg, id, envelope.TypeCancel, nil); !errors.Is(err, ErrState) {
		t.Fatalf("%v", err)
	}
	w.settle()
	if len(w.sent) != sent+1 || a.chains[id].follow == nil || a.chains[id].follow == old || a.chains[id].busy {
		t.Fatalf("sent %d more, newer key kept: %v, busy: %v", len(w.sent)-sent, a.chains[id].follow != nil && a.chains[id].follow != old, a.chains[id].busy)
	}
	// With the newer key the cancel goes.
	a.cfg.Directory = func(_ context.Context, d string) (*binding.Signed, error) { return w.devs[d].bind, nil }
	if err := a.Follow(bg, id, envelope.TypeCancel, nil); err != nil {
		t.Fatal(err)
	}
}

// A request that gets no answer ends in exactly one of two ways, and each is tested without waiting on a race:
// the caller's context ends first (it is already over), or the timer does (the answer never comes and no context
// ends). Both are "wait and ask again" for the outbox, except that a context that ended is its own error.
func TestPrekeyRequestEndsWithItsContextOrItsTimer(t *testing.T) {
	w := newWorld(t, "alice", "bob")
	w.onRelay = func(from, to, body string) (bool, string) { return false, "" } // the gateway swallows everything
	a := w.devs["alice"].node
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := a.requestPrekey(ctx, w.devs["bob"].bind, w.clock().Add(time.Minute)); !errors.Is(err, context.Canceled) {
		t.Fatalf("context: %v", err)
	}
	a.cfg.RequestTimeout = time.Millisecond
	if _, err := a.requestPrekey(bg, w.devs["bob"].bind, w.clock().Add(time.Minute)); !errors.Is(err, ErrTimeout) || !errors.Is(err, outbox.ErrOffline) {
		t.Fatalf("timer: %v", err)
	}
	if len(a.waiting) != 0 {
		t.Fatal("a request that ended is still waiting")
	}
}
