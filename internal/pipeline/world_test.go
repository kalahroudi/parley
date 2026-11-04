// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
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
	"github.com/kalahroudi/parley/internal/trust"
	"github.com/kalahroudi/parley/internal/tunnel"
)

var t0 = time.Unix(1_800_000_000, 0).UTC()

const tenant = "acme"

// world is a tenant of devices joined by a fake gateway. The gateway does what
// the Worker does with these messages (relay prekey frames, wrap sealed parts in
// an A2A event) and can be told to misbehave. Each device processes its events
// one at a time on its own goroutine, as the daemon does.
type world struct {
	t    *testing.T
	mu   sync.Mutex
	now  time.Time
	root ed25519.PrivateKey
	pub  ed25519.PublicKey
	devs map[string]*dev
	wg   sync.WaitGroup
	done chan struct{}
	once sync.Once

	// Hooks. Nil means honest.
	onRelay func(from, to, body string) (deliver bool, replace string)
	onWire  func(to string, wire []byte) [][]byte
	sent    []Outgoing // everything handed to the gateway, in order
	relayed []string   // every frame put on a tunnel
}

type dev struct {
	w      *world
	id     string
	owner  string
	sign   ed25519.PrivateKey
	bind   *binding.Signed
	pool   *prekey.Pool
	table  *replay.Table
	node   *Node
	online atomic.Bool
	allow  map[string]bool // owners refused when false
	q      chan tunnel.Event

	mu      sync.Mutex
	inbox   []Inbound
	updates []Update
	errs    []error
	onTask  func(Inbound) // runs inside OnInbound
}

func (w *world) clock() time.Time { w.mu.Lock(); defer w.mu.Unlock(); return w.now }
func (w *world) advance(d time.Duration) {
	w.mu.Lock()
	w.now = w.now.Add(d)
	w.mu.Unlock()
}

func newWorld(t *testing.T, ids ...string) *world {
	t.Helper()
	w := &world{t: t, now: t0, devs: map[string]*dev{}, done: make(chan struct{})}
	t.Cleanup(w.stop)
	var err error
	w.pub, w.root, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		w.add(id)
	}
	return w
}

func (w *world) add(id string) *dev {
	w.t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b, err := binding.Sign(w.root, binding.Binding{Tenant: tenant, Owner: id + "@acme.test", DeviceID: id, SigningKey: pub, Version: 1, NotAfter: t0.Add(binding.Lifetime)})
	if err != nil {
		w.t.Fatal(err)
	}
	d := &dev{w: w, id: id, owner: id + "@acme.test", sign: priv, bind: b, allow: map[string]bool{}, q: make(chan tunnel.Event, 64)}
	d.pool, err = prekey.New(prekey.Config{Tenant: tenant, DeviceID: id, SigningKeyID: KeyID(pub), BindingVersion: 1, Signer: priv, AllowUnlocked: true, SweepEvery: time.Hour, Now: w.clock})
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(d.pool.Close)
	d.table = replay.New(replay.Config{Now: w.clock})
	tr, err := binding.NewTracker(w.pub, nil)
	if err != nil {
		w.t.Fatal(err)
	}
	g, err := revocation.NewGuard(w.pub, tenant, nil, t0)
	if err != nil {
		w.t.Fatal(err)
	}
	td := &trust.Daemon{Tracker: tr, Guard: g, Tenant: tenant}
	if err := tr.Accept(b, t0); err != nil {
		w.t.Fatal(err)
	}
	list, _ := revocation.Next(w.root, tenant, nil, nil, t0)
	if err := g.Accept(list, t0); err != nil {
		w.t.Fatal(err)
	}
	d.node, err = New(Config{Tenant: tenant, Device: id, Signer: priv, Version: 1, Pool: d.pool, Replay: d.table, Trust: td,
		Directory: func(_ context.Context, device string) (*binding.Signed, error) {
			if o := w.get(device); o != nil {
				return o.bind, nil
			}
			return nil, fmt.Errorf("no such device: %w", outbox.ErrGone)
		},
		Allow:     func(owner string) bool { return !d.allow[owner] },
		Relay:     func(body string) error { return w.relay(id, body) },
		Gateway:   &fakeGW{w: w, from: id},
		OnInbound: d.onInbound, OnUpdate: d.onUpdate, Now: w.clock,
		RequestTimeout: 200 * time.Millisecond, CancelWait: 30 * time.Second,
		Outbox: outbox.Config{MinPoll: 2 * time.Millisecond, MaxPoll: 5 * time.Millisecond, Jitter: func(d time.Duration) time.Duration { return d }}})
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(d.node.Close)
	d.online.Store(true)
	w.mu.Lock()
	w.devs[id] = d
	w.mu.Unlock()
	go func() {
		for {
			select {
			case ev := <-d.q:
				err := d.node.HandleEvent(context.Background(), ev)
				d.mu.Lock()
				d.errs = append(d.errs, err)
				d.mu.Unlock()
				w.wg.Done()
			case <-w.done:
				return
			}
		}
	}()
	return d
}

func (d *dev) onInbound(in Inbound) {
	in.Content = bytes.Clone(in.Content)
	d.mu.Lock()
	d.inbox = append(d.inbox, in)
	f := d.onTask
	d.mu.Unlock()
	if f != nil {
		f(in)
	}
}

func (d *dev) onUpdate(u Update) {
	u.Content = bytes.Clone(u.Content)
	d.mu.Lock()
	d.updates = append(d.updates, u)
	d.mu.Unlock()
}

func (d *dev) lastErr() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.errs) == 0 {
		return nil
	}
	return d.errs[len(d.errs)-1]
}

func (d *dev) inboxLen() int       { d.mu.Lock(); defer d.mu.Unlock(); return len(d.inbox) }
func (d *dev) updateLen() int      { d.mu.Lock(); defer d.mu.Unlock(); return len(d.updates) }
func (d *dev) update(i int) Update { d.mu.Lock(); defer d.mu.Unlock(); return d.updates[i] }
func (d *dev) errAt(i int) error   { d.mu.Lock(); defer d.mu.Unlock(); return d.errs[i] }
func (d *dev) errCount() int       { d.mu.Lock(); defer d.mu.Unlock(); return len(d.errs) }

// deliver queues an event for a device's pipeline.
func (w *world) deliver(to, body string) {
	w.mu.Lock()
	d := w.devs[to]
	w.mu.Unlock()
	if d == nil {
		return
	}
	w.wg.Add(1)
	select {
	case d.q <- tunnel.Event{Body: body}:
	case <-w.done:
		w.wg.Done()
	}
}

// settle waits until every queued event has been handled.
func (w *world) settle() { w.wg.Wait() }

// relay is the gateway's side of a tunnel frame from a device.
func (w *world) relay(from, body string) error {
	w.mu.Lock()
	w.relayed = append(w.relayed, body)
	hook := w.onRelay
	w.mu.Unlock()
	var f map[string]any
	if err := json.Unmarshal([]byte(body), &f); err != nil {
		return err
	}
	to, _ := f["to"].(string)
	if hook != nil {
		deliver, replace := hook(from, to, body)
		if !deliver {
			return nil
		}
		if replace != "" {
			w.deliver(from, replace) // the gateway answers the requester itself
			return nil
		}
	}
	if d := w.get(to); d == nil || !d.online.Load() {
		if f["t"] == frames.KindPrekeyRequest {
			w.deliver(from, fmt.Sprintf(`{"t":"prekey_refused","id":%q,"from":%q,"reason":"offline"}`, f["id"], to))
		}
		return nil
	}
	delete(f, "to")
	f["from"] = from
	if f["t"] == frames.KindPrekeyRefused {
		f["reason"] = frames.ReasonRefused // the gateway names the reason; a target only declines
	}
	out, _ := json.Marshal(f)
	w.deliver(to, string(out))
	return nil
}

type fakeGW struct {
	w     *world
	from  string
	failv atomic.Pointer[error] // returned by Send/Cancel when set
}

func (g *fakeGW) Send(ctx context.Context, m Outgoing) error   { return g.route(m) }
func (g *fakeGW) Cancel(ctx context.Context, m Outgoing) error { return g.route(m) }

func (g *fakeGW) route(m Outgoing) error {
	w := g.w
	w.mu.Lock()
	w.sent = append(w.sent, m)
	hook := w.onWire
	w.mu.Unlock()
	if e := g.failv.Load(); e != nil {
		return *e
	}
	if d := w.get(m.Target); d == nil || !d.online.Load() {
		return fmt.Errorf("offline: %w", outbox.ErrOffline)
	}
	wires := [][]byte{m.Wire}
	if hook != nil {
		wires = hook(m.Target, m.Wire)
	}
	for _, wire := range wires {
		w.deliver(m.Target, event(wire))
	}
	return nil
}

// event is what the Worker pushes to a daemon for a sealed message.
func event(wire []byte) string {
	b, _ := json.Marshal(map[string]any{"a2a": "1.0", "task": map[string]any{"id": "x", "status": map[string]any{"state": "TASK_STATE_WORKING",
		"message": map[string]any{"messageId": "m", "parts": []map[string]string{{"raw": base64.StdEncoding.EncodeToString(wire), "mediaType": frames.SealedMediaType}},
			"metadata": map[string]any{"parley": map[string]any{"kind": "STATUS", "from": "liar"}}}}}})
	return string(b)
}

func (w *world) gw(id string) *fakeGW { return w.devs[id].node.cfg.Gateway.(*fakeGW) }

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// send submits a task and waits for the outbox to finish with it.
func (w *world) send(from, to string, content string) ([16]byte, outbox.Status) {
	w.t.Helper()
	id, err := w.devs[from].node.Submit(Request{Target: to, Content: []byte(content), Expiry: w.clock().Add(15 * time.Minute)})
	if err != nil {
		w.t.Fatal(err)
	}
	select {
	case <-w.devs[from].node.Done(id):
	case <-time.After(5 * time.Second):
		w.t.Fatal("sending never finished")
	}
	w.settle()
	st, _ := w.devs[from].node.Status(id)
	return id, st
}

// run sends a task and returns its id, failing unless it was sent and arrived.
func (w *world) run(from, to, content string) [16]byte {
	w.t.Helper()
	id, st := w.send(from, to, content)
	if st.State != outbox.Sent {
		w.t.Fatalf("task not sent: %+v", st)
	}
	eventually(w.t, "the bot to get the task", func() bool { return w.devs[to].inboxLen() > 0 })
	return id
}

type ed25519Pub = ed25519.PublicKey

func tunnelEvent(body string) tunnel.Event { return tunnel.Event{Body: body} }

func (g *fakeGW) setFail(err error) {
	if err == nil {
		g.failv.Store(nil)
		return
	}
	g.failv.Store(&err)
}

func (w *world) get(id string) *dev {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.devs[id]
}

func (w *world) stop() { w.once.Do(func() { close(w.done) }) }

func deliveredOf(h envelope.Header, pt []byte) receive.Delivered {
	return receive.Delivered{Header: h, Owner: "o", Plaintext: pt}
}
