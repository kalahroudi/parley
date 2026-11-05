// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/frames"
	"github.com/kalahroudi/parley/internal/outbox"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/receive"
)

// Request is a task to send.
type Request struct {
	Target  string // the target bot's device id
	Content []byte // at most MaxContent; the node keeps its own copy
	Expiry  time.Time
}

// Submit queues a task. It returns at once with the task id; the outbox waits
// for the target (nothing is sent, and nothing is stored but in memory) and
// Status/Done report the result of sending. Progress after that arrives
// through OnUpdate and State.
func (n *Node) Submit(r Request) ([16]byte, error) {
	var id [16]byte
	if r.Target == "" || !frames.ValidID(r.Target) || len(r.Content) > MaxContent {
		return id, outbox.ErrInvalid
	}
	n.rand(id[:])
	key := taskHex(id)
	n.mu.Lock()
	if len(n.queue) >= n.cfg.MaxPending || len(n.chains) >= n.cfg.MaxTasks {
		n.mu.Unlock()
		return id, ErrBusy
	}
	n.queue[key] = &queued{id: id, content: append([]byte(nil), r.Content...)}
	n.mu.Unlock()
	if err := n.box.Submit(outbox.Task{ID: key, Target: r.Target, Expiry: r.Expiry}); err != nil {
		n.dropQueued(key)
		return id, err
	}
	// The content is needed for every attempt while the target is offline, and
	// not a moment after sending has finished, however it finished.
	go func() {
		<-n.box.Done(key)
		n.dropQueued(key)
	}()
	return id, nil
}

// Status is the outbox's view of a task that is still being sent.
func (n *Node) Status(id [16]byte) (outbox.Status, bool) { return n.box.Status(taskHex(id)) }

// Done is closed when sending has finished, one way or the other.
func (n *Node) Done(id [16]byte) <-chan struct{} { return n.box.Done(taskHex(id)) }

// Abandon stops waiting for a task that has not been sent yet.
func (n *Node) Abandon(id [16]byte) error {
	return n.box.Cancel(taskHex(id)) // the content is dropped when sending is done, which this ends
}

func (n *Node) dropQueued(key string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if q := n.queue[key]; q != nil {
		clear(q.content)
		delete(n.queue, key)
	}
}

// ready refuses to send unless this device is enrolled at the binding version
// its prekeys and headers carry, and the revocation list it holds is fresh and
// does not revoke it. Nothing has been generated or sent yet.
func (n *Node) ready(now time.Time) error {
	if v, ok := n.cfg.Trust.Tracker.Version(n.cfg.Tenant, n.cfg.Device); !ok || v != n.cfg.Version {
		return ErrNotReady
	}
	return n.cfg.Trust.Guard.CheckSend(n.cfg.Device, now)
}

// sendTask is the outbox's Send hook: everything between "the target may be
// online" and "the sealed task is with the gateway".
func (n *Node) sendTask(ctx context.Context, t outbox.Task) error {
	n.mu.Lock()
	q := n.queue[t.ID]
	n.mu.Unlock()
	if q == nil {
		return ErrUnknown
	}
	id := q.id
	now := n.cfg.Now()
	if err := n.ready(now); err != nil {
		return err
	}
	tb, err := n.peer(ctx, t.Target, 0)
	if err != nil {
		if errors.Is(err, outbox.ErrGone) {
			return err // the directory says there is no such device
		}
		return fmt.Errorf("%w: %w", outbox.ErrOffline, err) // the directory could not be asked: nothing was sent, try again
	}
	if err := n.cfg.Trust.AuthorizeSend(tb, now); err != nil {
		return err
	}

	// The reply key comes from our own pool: private half in locked memory.
	var nonce [16]byte
	n.rand(nonce[:])
	rpk, err := n.cfg.Pool.Issue(prekey.Request{Caller: t.Target, Nonce: nonce[:], TaskExpiry: t.Expiry})
	if err != nil {
		if errors.Is(err, prekey.ErrRateLimited) || errors.Is(err, prekey.ErrPoolFull) {
			// Too many replies still outstanding from this target (or no free slot): that
			// clears as they arrive, so wait for the task's deadline rather than fail it.
			return fmt.Errorf("%w: %w", outbox.ErrOffline, err)
		}
		return err
	}
	registered := false
	defer func() {
		if !registered {
			_ = n.cfg.Pool.Consume(rpk.ID)
		}
	}()

	sp, err := n.requestPrekey(ctx, tb, t.Expiry)
	if err != nil {
		return err
	}
	h := envelope.Header{Tenant: n.cfg.Tenant, SenderDevice: n.cfg.Device, SenderKeyID: KeyID(n.ownPub), BindingVersion: n.cfg.Version,
		TargetDevice: t.Target, PrekeyID: receive.PrekeyID(sp.ID), TaskID: id, ContextID: taskHex(id), Type: envelope.TypeTask,
		IssuedAt: now, Expiry: t.Expiry, RPK: rpk.PublicKey, Prekey: frames.EncodePrekey(sp)}
	inner := frames.PackInner(rpk, q.content)
	m, err := envelope.SealPadded(n.cfg.Signer, sp.PublicKey, h, inner)
	clear(inner)
	if err != nil {
		return err
	}

	// Register before sending: the first reply can beat SendMessage's answer.
	n.mu.Lock()
	n.chains[id] = &chain{role: caller, peer: t.Target, context: h.ContextID, expiry: t.Expiry, recvSeq: 1, recvLast: hashOf(h),
		sendLast: hashOf(h), reply: rpk, hasOwn: true, last: envelope.TypeTask}
	n.mu.Unlock()
	registered = true
	if err := n.cfg.Gateway.Send(ctx, Outgoing{Wire: m.Marshal(), Task: t.ID, Kind: "TASK", Target: t.Target}); err != nil {
		n.mu.Lock()
		if c := n.chains[id]; c != nil {
			n.forget(id, c)
		}
		n.mu.Unlock()
		return err
	}
	return nil
}

// requestPrekey asks the target, through the relay, for a one-time prekey and
// verifies the answer against the target's root-signed binding and our nonce.
func (n *Node) requestPrekey(ctx context.Context, tb *binding.Signed, expiry time.Time) (*prekey.Signed, error) {
	var rid, nonce [16]byte
	n.rand(rid[:])
	n.rand(nonce[:])
	reqID := hex.EncodeToString(rid[:])
	body, err := frames.RequestPrekey(reqID, tb.DeviceID, nonce[:], expiry)
	if err != nil {
		return nil, err
	}
	w := &waiter{target: tb.DeviceID, ch: make(chan frames.Relay, 1)}
	n.mu.Lock()
	if len(n.waiting) >= n.cfg.MaxPending {
		n.mu.Unlock()
		return nil, ErrBusy
	}
	n.waiting[reqID] = w
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.waiting, reqID)
		n.mu.Unlock()
	}()
	if err := n.cfg.Relay(body); err != nil {
		return nil, fmt.Errorf("%w: %w", outbox.ErrOffline, err) // not on the wire: nothing was asked
	}
	wait := time.NewTimer(n.cfg.RequestTimeout)
	defer wait.Stop()
	select {
	case a := <-w.ch:
		return n.checkAnswer(a, tb, nonce[:])
	case <-wait.C:
		return nil, fmt.Errorf("%w: %w", outbox.ErrOffline, ErrTimeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (n *Node) checkAnswer(a frames.Relay, tb *binding.Signed, nonce []byte) (*prekey.Signed, error) {
	if a.Kind == frames.KindPrekeyRefused && (a.Reason == frames.ReasonOffline || a.Reason == frames.ReasonRateLimited) {
		return nil, fmt.Errorf("%w: %s", outbox.ErrOffline, a.Reason) // the target has not seen the request: wait and ask again
	}
	if a.Kind != frames.KindPrekeyReply {
		return nil, ErrRefused
	}
	sp, err := frames.DecodePrekey(a.Prekey)
	if err != nil {
		return nil, ErrPrekey
	}
	err = prekey.Verify(ed25519.PublicKey(tb.SigningKey), sp, prekey.Expect{Tenant: n.cfg.Tenant, DeviceID: tb.DeviceID, SigningKeyID: KeyID(tb.SigningKey),
		Caller: n.cfg.Device, Nonce: nonce, BindingVersion: tb.Version, Now: n.cfg.Now()})
	if err != nil {
		return nil, ErrPrekey
	}
	return sp, nil
}

// answerPrekey hands an answer to the sender waiting for it. An answer nobody
// waits for, or from a device other than the one asked, is dropped.
func (n *Node) answerPrekey(r *frames.Relay) {
	n.mu.Lock()
	w := n.waiting[r.ID]
	if w != nil && w.target == r.Peer {
		delete(n.waiting, r.ID)
	} else {
		w = nil
	}
	n.mu.Unlock()
	if w != nil {
		w.ch <- *r // buffered: never blocks, and only one answer is taken
	}
}

// servePrekey answers a peer's prekey request: the target checks the caller
// itself (binding, revocation, allowlist), then issues a fresh key bound to the
// caller and its nonce. The gateway only relays.
func (n *Node) servePrekey(ctx context.Context, r *frames.Relay) error {
	refuse := func(err error) error {
		if body, e := frames.RefusePrekey(r.ID, r.Peer); e == nil {
			_ = n.cfg.Relay(body)
		}
		return err
	}
	b, err := n.peer(ctx, r.Peer, 0)
	if err == nil {
		err = n.admitPeer(b, true)
	}
	if err != nil {
		return refuse(ErrPeer)
	}
	sp, err := n.cfg.Pool.Issue(prekey.Request{Caller: r.Peer, Nonce: r.Nonce, TaskExpiry: r.TaskExpiry})
	if err != nil {
		return refuse(err)
	}
	body, err := frames.ReplyPrekey(r.ID, r.Peer, frames.EncodePrekey(sp))
	if err == nil {
		err = n.cfg.Relay(body)
	}
	if err != nil {
		_ = n.cfg.Pool.Consume(sp.ID) // nobody will use it
		return err
	}
	return nil
}

// Respond is the target's reply to a task: STATUS, INPUT_REQUIRED, RESULT or
// ERROR (or the acknowledgment of a CANCEL). It is sealed to the caller's reply
// key. A message that continues the task carries a fresh key for the caller's
// follow-up, and the previous one, if unused, is erased once this one is sent; a
// final message ends the task.
func (n *Node) Respond(ctx context.Context, id [16]byte, typ envelope.Type, content []byte) error {
	if len(content) > MaxContent {
		return outbox.ErrInvalid
	}
	switch typ {
	case envelope.TypeStatus, envelope.TypeInputRequired, envelope.TypeResult, envelope.TypeError, envelope.TypeCancel:
	default:
		return ErrState
	}
	now := n.cfg.Now()
	if err := n.ready(now); err != nil {
		return err
	}
	n.mu.Lock()
	c := n.chains[id]
	if c == nil || c.role != target || c.done || c.busy || (c.cancel && typ != envelope.TypeCancel) || (typ == envelope.TypeCancel && !c.cancel) {
		n.mu.Unlock()
		return ErrState
	}
	c.busy = true
	peer, reply := c.peer, c.reply
	n.mu.Unlock()
	if err := n.cfg.Trust.Guard.CheckSend(peer, now); err != nil {
		n.release(c)
		return err
	}
	var next *prekey.Signed
	if !isFinal(typ) {
		var nonce [16]byte
		n.rand(nonce[:])
		var err error
		if next, err = n.cfg.Pool.Issue(prekey.Request{Caller: peer, Nonce: nonce[:], TaskExpiry: c.expiry}); err != nil {
			n.release(c)
			return err
		}
	}
	h := envelope.Header{Tenant: n.cfg.Tenant, SenderDevice: n.cfg.Device, SenderKeyID: KeyID(n.ownPub), BindingVersion: n.cfg.Version,
		TargetDevice: peer, PrekeyID: receive.PrekeyID(reply.ID), TaskID: id, ContextID: c.context, Seq: c.sendSeq + 1, Type: typ,
		IssuedAt: now, Expiry: c.expiry, PrevHash: c.sendLast}
	inner := frames.PackInner(next, content)
	m, err := envelope.SealPadded(n.cfg.Signer, reply.PublicKey, h, inner)
	clear(inner)
	if err == nil {
		err = n.cfg.Gateway.Send(ctx, Outgoing{Wire: m.Marshal(), Task: taskHex(id), Kind: kindName[typ], Target: peer, Seq: h.Seq})
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	c.busy = false
	if err != nil {
		// Nothing was delivered, so the caller still holds the old follow-up
		// key; the fresh one is of no use.
		if next != nil {
			_ = n.cfg.Pool.Consume(next.ID)
		}
		return err
	}
	if c.hasOwn {
		_ = n.cfg.Pool.Consume(c.follow.ID) // the caller now holds the new key
	}
	c.sendSeq, c.sendLast, c.last = h.Seq, hashOf(h), typ
	c.follow, c.hasOwn, c.asked = next, next != nil, typ == envelope.TypeInputRequired
	if isFinal(typ) {
		c.done = true
	}
	return nil
}

func (n *Node) release(c *chain) {
	n.mu.Lock()
	c.busy = false
	n.mu.Unlock()
}

// Follow is the caller's follow-up on a task: REPLY to a question, or CANCEL.
// It is sealed to the one-time key the target put in its last message, which
// can be used once; with none, wait for the target's next message (ErrNoKey).
// A CANCEL keeps the reply key for CancelWait so the target's acknowledgment can
// be read; nothing else arriving in the meantime is accepted.
func (n *Node) Follow(ctx context.Context, id [16]byte, typ envelope.Type, content []byte) error {
	if len(content) > MaxContent {
		return outbox.ErrInvalid
	}
	if typ != envelope.TypeReply && typ != envelope.TypeCancel {
		return ErrState
	}
	now := n.cfg.Now()
	if err := n.ready(now); err != nil {
		return err
	}
	n.mu.Lock()
	c := n.chains[id]
	if c == nil {
		n.mu.Unlock()
		return ErrUnknown
	}
	if c.role != caller || c.done || c.cancel || c.busy || (typ == envelope.TypeReply && !c.input) {
		n.mu.Unlock()
		return ErrState
	}
	if c.follow == nil {
		n.mu.Unlock()
		return ErrNoKey
	}
	c.busy = true
	peer, key := c.peer, c.follow
	n.mu.Unlock()
	tb, err := n.peer(ctx, peer, 0)
	if err == nil {
		err = n.cfg.Trust.AuthorizeSend(tb, now)
	}
	if err != nil {
		n.release(c)
		return err
	}
	h := envelope.Header{Tenant: n.cfg.Tenant, SenderDevice: n.cfg.Device, SenderKeyID: KeyID(n.ownPub), BindingVersion: n.cfg.Version,
		TargetDevice: peer, PrekeyID: receive.PrekeyID(key.ID), TaskID: id, ContextID: c.context, Seq: c.sendSeq + 1, Type: typ,
		IssuedAt: now, Expiry: c.expiry, PrevHash: c.sendLast}
	inner := frames.PackInner(nil, content)
	m, err := envelope.SealPadded(n.cfg.Signer, key.PublicKey, h, inner)
	clear(inner)
	if err != nil {
		n.release(c)
		return err
	}
	// The target's key is good for one message: it is spent from here on,
	// whether or not the send works (a failed send may still have reached it).
	// If a newer reply came in meanwhile it brought a newer key, and the one we
	// sealed to is already erased at the target: nothing is sent, ask again.
	n.mu.Lock()
	if c != n.chains[id] || c.done || c.follow != key {
		c.busy = false
		n.mu.Unlock()
		return ErrState
	}
	c.follow, c.sendSeq, c.sendLast, c.busy = nil, h.Seq, hashOf(h), false
	if typ == envelope.TypeCancel {
		c.cancel, c.cancelBy = true, now.Add(n.cfg.CancelWait)
	} else {
		c.input = false
	}
	n.mu.Unlock()
	out := Outgoing{Wire: m.Marshal(), Task: taskHex(id), Kind: kindName[typ], Target: peer, Seq: h.Seq}
	if typ == envelope.TypeCancel {
		return n.cfg.Gateway.Cancel(ctx, out)
	}
	return n.cfg.Gateway.Send(ctx, out)
}
