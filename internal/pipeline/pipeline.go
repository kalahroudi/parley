// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package pipeline is a daemon's message path, both directions, composed from
// the packages that hold the guarantees: internal/receive (the at-most-once
// order), internal/prekey (one-time keys in locked memory), internal/envelope
// (HPKE and signed transcripts), internal/replay, internal/binding and
// internal/revocation (through internal/trust), and internal/outbox (waiting for
// an offline target). This package adds only the wiring and the per-task chain.
//
// Inbound, for every tunnel event: parse it (internal/frames), then
//
//   - a prekey request from a peer: check the peer (root-signed binding, not
//     revoked, owner allowlist), issue a one-time prekey and answer through the
//     relay;
//   - an answer to our own request: hand it to the sender waiting for it;
//   - a sealed message: fetch the sender's binding if needed and give it to a
//     receiver, which verifies, opens, erases the key, acknowledges and only
//     then calls us back with the plaintext. The plaintext reaches the bot
//     (OnInbound) or the caller (OnUpdate) from that callback and never earlier.
//
// Outbound: Submit queues a task with the outbox, which waits for the target to
// be reachable. Sending then runs, in this order and with nothing on the wire
// before the last check passes: the target's binding and the revocation list
// (trust.Daemon.AuthorizeSend), this device's own standing, a fresh reply key,
// the prekey request and its verification against the target's binding and our
// nonce, sealing, and SendMessage to the gateway. Follow-ups (Respond for the
// target, Follow for the caller) continue the task's chain.
//
// The chain. Each direction of a task is a chain rooted at the TASK header:
// sequence numbers 1, 2, ... and the hash of the sender's previous message. A
// message that does not continue its chain is refused before its key is spent
// (receive.Config.Admit), so reordered, replayed or foreign messages cannot burn
// keys. Keys:
//
//   - the target seals every reply to the caller's reply key (rpk), which stays
//     until the last reply, CANCEL or the task's expiry and is then erased;
//   - the caller seals every follow-up to the one-time key the target put in its
//     last message; the target erases it on receipt and issues the next with its
//     next message. A caller with no such key waits for the target's next message.
//
// What this package does not do: it holds no plaintext beyond a callback, writes
// no logs and keeps nothing on disk. Errors are fixed sentinels. A daemon crash
// loses every in-flight task and the callers resend, by design.
package pipeline

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/frames"
	"github.com/kalahroudi/parley/internal/outbox"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/receive"
	"github.com/kalahroudi/parley/internal/replay"
	"github.com/kalahroudi/parley/internal/trust"
	"github.com/kalahroudi/parley/internal/tunnel"
)

// Limits and defaults. MaxContent keeps the padded payload inside the largest
// bucket the gateway relays in one tunnel frame (gateway/src/parts.ts); bigger
// content travels as an encrypted file.
const (
	MaxContent            = 1<<19 - 2<<10
	DefaultMaxTasks       = 1024
	DefaultMaxPeers       = 1024
	DefaultMaxPending     = 256
	DefaultRequestTimeout = 10 * time.Second
	DefaultCancelWait     = 30 * time.Second
	lookupTimeout         = 5 * time.Second
)

var (
	ErrConfig   = errors.New("pipeline: incomplete configuration")
	ErrNotReady = errors.New("pipeline: this device is not ready to send (not enrolled, or its binding changed since start)")
	ErrUnknown  = errors.New("pipeline: no such task")
	ErrBusy     = errors.New("pipeline: too many tasks in flight")
	ErrState    = errors.New("pipeline: the task's state does not allow this message")
	ErrNoKey    = errors.New("pipeline: no key to seal this follow-up to yet")
	ErrPeer     = errors.New("pipeline: peer is unknown, revoked, or not permitted")
	ErrPrekey   = errors.New("pipeline: the target's prekey is refused")
	ErrRefused  = errors.New("pipeline: the target refused to issue a prekey")
	ErrTimeout  = errors.New("pipeline: no prekey answer in time")
	ErrInner    = errors.New("pipeline: sealed payload is malformed")
)

// KeyID names a signing key in headers and prekeys: the first 8 bytes, in hex.
func KeyID(pub ed25519.PublicKey) string { return hex.EncodeToString(pub[:8]) }

// Outgoing is one message handed to the gateway.
type Outgoing struct {
	Wire   []byte // the envelope wire message
	Task   string // lowercase hex of the task id (the gateway's name for it)
	Kind   string // TASK, STATUS, INPUT_REQUIRED, RESULT, ERROR, CANCEL or REPLY
	Target string
	Seq    uint64
}

// Gateway sends sealed messages through the gateway's A2A endpoint. An error
// wrapping outbox.ErrOffline must mean the message was not delivered.
type Gateway interface {
	Send(ctx context.Context, m Outgoing) error
	Cancel(ctx context.Context, m Outgoing) error
}

// Inbound is what the bot receives: a new task, a follow-up from the caller, or
// a cancel. Content is valid only during the call.
type Inbound struct {
	Type    envelope.Type // TypeTask, TypeReply or TypeCancel
	TaskID  [16]byte
	Context string
	Caller  string // the caller's device id, from the signed header
	Owner   string // the caller's owner, from its root-signed binding
	Content []byte
	Expiry  time.Time
}

// Update is a message about a task this device sent. Type is the signed message
// type, which is authoritative; the gateway's state code is only a hint.
// Content is valid only during the call. Expired is set when the task ran out
// of time without a final message, or a cancel went unacknowledged (Type is then
// TypeError and Content is nil).
type Update struct {
	Type    envelope.Type // TypeStatus, TypeInputRequired, TypeResult, TypeError or TypeCancel
	TaskID  [16]byte
	Content []byte
	Expired bool
}

// Config wires a Node to the device's own state.
type Config struct {
	Tenant  string
	Device  string
	Signer  ed25519.PrivateKey
	Version uint64 // this device's binding version; the pool was built with it

	Pool   *prekey.Pool
	Replay *replay.Table
	Trust  *trust.Daemon
	// Directory returns a peer's current root-signed binding. It is only a
	// source: every binding is verified against the pinned root and the rollback
	// store before it is used.
	Directory func(ctx context.Context, device string) (*binding.Signed, error)
	// Allow is the owner's allowlist for callers into this device's bots.
	Allow func(owner string) bool
	// Relay puts one frame on the tunnel (tunnel.Client.Send).
	Relay   func(body string) error
	Gateway Gateway

	OnInbound func(Inbound)
	OnUpdate  func(Update)

	MaxTasks, MaxPeers, MaxPending int
	RequestTimeout, CancelWait     time.Duration
	Outbox                         outbox.Config // Presence and Send are set by New
	Now                            func() time.Time
	Rand                           io.Reader
	Fault                          func(receive.Stage) error // test seam, passed to the receivers
}

type role uint8

const (
	caller role = iota + 1
	target
)

// chain is the state of one task on this device.
type chain struct {
	role     role
	peer     string
	owner    string // target only
	context  string
	expiry   time.Time
	recvSeq  uint64 // next sequence number expected from the peer
	recvLast []byte // hash of the last message accepted from the peer
	sendSeq  uint64
	sendLast []byte

	reply    *prekey.Signed // the caller's reply key (rpk): held by the caller's pool
	follow   *prekey.Signed // the target's key for the caller's next follow-up: held by the target's pool
	hasOwn   bool           // we hold the key above in our pool
	input    bool           // the target asked a question (caller side), so REPLY is allowed
	asked    bool           // the caller's REPLY is awaited (target side)
	cancel   bool           // CANCEL requested (caller) or received (target)
	cancelBy time.Time      // caller: how long the reply key stays to read the acknowledgment
	done     bool           // a final message was sent or received
	busy     bool           // a message of ours is being sent: one at a time, so sequence numbers cannot repeat
	last     envelope.Type  // the last message type accepted or sent: the task's state
}

type waiter struct {
	target string
	ch     chan frames.Relay
}

type queued struct {
	id      [16]byte
	content []byte
}

// Node is one device's pipeline. It is safe for concurrent use.
type Node struct {
	cfg    Config
	rxIn   *receive.Receiver // tasks, follow-ups and cancels addressed to our bots
	rxOut  *receive.Receiver // replies to tasks we sent
	box    *outbox.Outbox
	ownPub ed25519.PublicKey

	mu      sync.Mutex
	chains  map[[16]byte]*chain
	peers   map[string]*binding.Signed
	waiting map[string]*waiter
	queue   map[string]*queued
}

// New builds a Node. Close it when the daemon stops.
func New(cfg Config) (*Node, error) {
	if cfg.Tenant == "" || cfg.Device == "" || len(cfg.Signer) != ed25519.PrivateKeySize || cfg.Version == 0 || cfg.Pool == nil ||
		cfg.Replay == nil || cfg.Trust == nil || cfg.Directory == nil || cfg.Allow == nil || cfg.Relay == nil || cfg.Gateway == nil ||
		cfg.OnInbound == nil || cfg.OnUpdate == nil {
		return nil, ErrConfig
	}
	cfg.MaxTasks = orInt(cfg.MaxTasks, DefaultMaxTasks)
	cfg.MaxPeers = orInt(cfg.MaxPeers, DefaultMaxPeers)
	cfg.MaxPending = orInt(cfg.MaxPending, DefaultMaxPending)
	cfg.RequestTimeout = orDur(cfg.RequestTimeout, DefaultRequestTimeout)
	cfg.CancelWait = orDur(cfg.CancelWait, DefaultCancelWait)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	n := &Node{cfg: cfg, ownPub: cfg.Signer.Public().(ed25519.PublicKey), chains: map[[16]byte]*chain{},
		peers: map[string]*binding.Signed{}, waiting: map[string]*waiter{}, queue: map[string]*queued{}}
	rc := receive.Config{Tenant: cfg.Tenant, Device: cfg.Device, Pool: cfg.Pool, Replay: cfg.Replay, Bindings: cfg.Trust.Tracker,
		Lookup: n.cached, Revoked: cfg.Trust.Guard.IsRevoked, Now: cfg.Now, Fault: cfg.Fault}
	in := rc
	in.Allow, in.Admit = cfg.Allow, n.admitIn
	out := rc
	out.Allow, out.Admit, out.Keep = func(string) bool { return true }, n.admitOut, n.keepReplyKey
	oc := cfg.Outbox
	oc.Presence = func(context.Context, string) (bool, error) { return true, nil } // the relay answers "offline"
	oc.Send = n.sendTask
	if oc.Now == nil {
		oc.Now = cfg.Now
	}
	var err error
	if n.rxIn, err = receive.New(in); err == nil {
		if n.rxOut, err = receive.New(out); err == nil {
			n.box, err = outbox.New(oc) // cannot fail with both hooks set; folded into the one error return
		}
	}
	if err != nil {
		return nil, err
	}
	return n, nil
}

func orInt(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

func orDur(v, d time.Duration) time.Duration {
	if v <= 0 {
		return d
	}
	return v
}

// Close fails the tasks still waiting and erases every key held for a task.
func (n *Node) Close() {
	n.box.Close()
	n.mu.Lock()
	defer n.mu.Unlock()
	for id, c := range n.chains {
		n.forget(id, c)
	}
	for _, q := range n.queue {
		clear(q.content)
	}
	clear(n.queue)
}

// forget erases the keys held for a chain and drops it. Called with mu held.
func (n *Node) forget(id [16]byte, c *chain) {
	n.eraseKey(c)
	delete(n.chains, id)
}

// eraseKey consumes the pool key a chain holds, if any. Called with mu held.
func (n *Node) eraseKey(c *chain) {
	if !c.hasOwn {
		return
	}
	k := c.follow
	if c.role == caller {
		k = c.reply
	}
	_ = n.cfg.Pool.Consume(k.ID) // already gone is fine: the goal is that it is gone
	c.hasOwn = false
}

// cached is the receivers' view of a sender's binding: only what HandleEvent
// fetched for this very message.
func (n *Node) cached(device string) (*binding.Signed, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if b := n.peers[device]; b != nil {
		return b, nil
	}
	return nil, ErrPeer
}

// peer returns the binding of a device, fetching it from the directory when it
// is not held, is for another version than the message names (want, if not
// zero), or has expired. The result is not trusted until the receivers or
// admitPeer verify it.
func (n *Node) peer(ctx context.Context, device string, want uint64) (*binding.Signed, error) {
	now := n.cfg.Now()
	n.mu.Lock()
	b := n.peers[device]
	n.mu.Unlock()
	if b != nil && (want == 0 || b.Version == want) && now.Before(b.NotAfter) {
		return b, nil
	}
	lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	b, err := n.cfg.Directory(lctx, device)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPeer, err)
	}
	if b == nil || b.Tenant != n.cfg.Tenant || b.DeviceID != device {
		return nil, ErrPeer
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, held := n.peers[device]; !held && len(n.peers) >= n.cfg.MaxPeers {
		for k := range n.peers { // any one: the cache only saves a lookup
			delete(n.peers, k)
			break
		}
	}
	n.peers[device] = b
	return b, nil
}

// admitPeer is the checks on a peer that need no signature: the same ones the
// receivers make, applied to a prekey request.
func (n *Node) admitPeer(b *binding.Signed, owner bool) error {
	if b.DeviceID == n.cfg.Device || n.cfg.Trust.Guard.IsRevoked(b.DeviceID) {
		return ErrPeer
	}
	if err := n.cfg.Trust.Tracker.Accept(b, n.cfg.Now()); err != nil {
		return ErrPeer
	}
	if owner && !n.cfg.Allow(b.Owner) {
		return ErrPeer
	}
	return nil
}

func (n *Node) rand(b []byte) {
	if _, err := io.ReadFull(n.cfg.Rand, b); err != nil {
		panic("pipeline: no randomness") // an unreadable random source is not recoverable; a key made without it would be worse
	}
}

func hashOf(h envelope.Header) []byte { s := h.Hash(); return s[:] }

func taskHex(id [16]byte) string { return hex.EncodeToString(id[:]) }

var kindName = map[envelope.Type]string{
	envelope.TypeTask: "TASK", envelope.TypeStatus: "STATUS", envelope.TypeInputRequired: "INPUT_REQUIRED",
	envelope.TypeResult: "RESULT", envelope.TypeError: "ERROR", envelope.TypeCancel: "CANCEL", envelope.TypeReply: "REPLY",
}

func isFinal(t envelope.Type) bool {
	return t == envelope.TypeResult || t == envelope.TypeError || t == envelope.TypeCancel
}

// HandleEvent processes one tunnel event. It returns a fixed-text error for a
// message that was refused or dropped (the caller logs the class, never the
// message) and nil for one that was handled. Events must be passed in order,
// one at a time, as the tunnel delivers them.
func (n *Node) HandleEvent(ctx context.Context, ev tunnel.Event) error {
	e, err := frames.ParseEvent(ev.Body)
	if err != nil {
		return err
	}
	// Fail closed: with no fresh revocation list, or none that clears the sender, or no standing of our own,
	// nothing is processed and nothing is answered (the same checks that gate sending).
	if e.Relay == nil || e.Relay.Kind == frames.KindPrekeyRequest {
		if err := n.ready(n.cfg.Now()); err != nil {
			return err
		}
	}
	if e.Relay != nil {
		switch e.Relay.Kind {
		case frames.KindPrekeyRequest:
			if err := n.cfg.Trust.Guard.CheckSend(e.Relay.Peer, n.cfg.Now()); err != nil {
				return err
			}
			return n.servePrekey(ctx, e.Relay)
		default:
			n.answerPrekey(e.Relay)
			return nil
		}
	}
	m, err := envelope.Unmarshal(e.Sealed)
	if err != nil {
		return err
	}
	h := m.Header
	if err := n.cfg.Trust.Guard.CheckSend(h.SenderDevice, n.cfg.Now()); err != nil {
		return err
	}
	// A sender that is not who the header says fails the receivers' checks; the
	// fetch below only supplies the binding they compare against.
	if _, err := n.peer(ctx, h.SenderDevice, h.BindingVersion); err != nil {
		return err
	}
	rx := n.rxOut
	switch h.Type {
	case envelope.TypeTask, envelope.TypeReply:
		rx = n.rxIn
	case envelope.TypeCancel:
		n.mu.Lock()
		if c := n.chains[h.TaskID]; c != nil && c.role == target {
			rx = n.rxIn
		}
		n.mu.Unlock()
	}
	exec := n.executeOut
	if rx == n.rxIn {
		exec = n.executeIn
	}
	return rx.Receive(m, func() error { return nil }, exec)
}

// keepReplyKey: a reply that does not end the task leaves the reply key for the next.
func (n *Node) keepReplyKey(h envelope.Header) bool { return !isFinal(h.Type) }

// admitIn judges a message addressed to our bots against the chain, before its
// key can be spent.
func (n *Node) admitIn(h envelope.Header) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := n.chains[h.TaskID]
	if h.Type == envelope.TypeTask {
		if c != nil || len(n.chains) >= n.cfg.MaxTasks {
			return ErrBusy
		}
		return nil
	}
	if c == nil || c.role != target || c.done || h.SenderDevice != c.peer || h.Seq != c.recvSeq || !bytes.Equal(h.PrevHash, c.recvLast) {
		return ErrState
	}
	if (h.Type == envelope.TypeReply && !c.asked) || c.follow == nil || !c.hasOwn || h.PrekeyID != receive.PrekeyID(c.follow.ID) {
		return ErrState // not a question we asked, or sealed to some key other than the one we issued for this follow-up
	}
	return nil
}

// admitOut judges a reply to a task we sent.
func (n *Node) admitOut(h envelope.Header) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := n.chains[h.TaskID]
	if c == nil || c.role != caller || c.done || h.SenderDevice != c.peer || h.Seq != c.recvSeq || !bytes.Equal(h.PrevHash, c.recvLast) {
		return ErrState
	}
	if c.cancel && h.Type != envelope.TypeCancel {
		return ErrState // a reply after we asked to cancel; only the acknowledgment is read
	}
	if c.reply == nil || h.PrekeyID != receive.PrekeyID(c.reply.ID) {
		return ErrState // sealed to some other key of ours
	}
	if h.Type == envelope.TypeInputRequired && c.input {
		return ErrState
	}
	return nil
}

// unpack strips the padding and reads the next-key and content from a plaintext
// that receive handed over. The content aliases pt.
func unpack(pt []byte) (*prekey.Signed, []byte, error) {
	p, err := envelope.Unpad(pt)
	if err != nil {
		return nil, nil, ErrInner
	}
	next, content, err := frames.UnpackInner(p)
	if err != nil {
		return nil, nil, ErrInner
	}
	return next, content, nil
}

// checkNext verifies a key the peer sent for our next message, against the
// peer's root-signed binding. The nonce is the key's own: there was no request.
func (n *Node) checkNext(next *prekey.Signed, from string, want []byte) error {
	b, err := n.cached(from)
	if err != nil {
		return err
	}
	if next == nil || (want != nil && !bytes.Equal(next.PublicKey, want)) {
		return ErrInner
	}
	if prekey.Verify(ed25519.PublicKey(b.SigningKey), next, prekey.Expect{Tenant: n.cfg.Tenant, DeviceID: from, SigningKeyID: KeyID(b.SigningKey),
		Caller: n.cfg.Device, Nonce: next.Nonce, BindingVersion: b.Version, Now: n.cfg.Now()}) != nil {
		return ErrPrekey
	}
	return nil
}

// executeIn runs after a message to our bots was opened, the key erased and
// the acknowledgment sent.
func (n *Node) executeIn(d receive.Delivered) error {
	h := d.Header
	next, content, err := unpack(d.Plaintext)
	if err != nil {
		return err
	}
	in := Inbound{Type: h.Type, TaskID: h.TaskID, Context: h.ContextID, Caller: h.SenderDevice, Owner: d.Owner, Expiry: h.Expiry}
	switch h.Type {
	case envelope.TypeTask:
		// The inner next-key is the caller's reply key: it must be the key the
		// header names, signed by the caller for this device.
		if err := n.checkNext(next, h.SenderDevice, h.RPK); err != nil {
			return err
		}
		n.mu.Lock()
		if len(n.chains) >= n.cfg.MaxTasks || n.chains[h.TaskID] != nil {
			n.mu.Unlock()
			return ErrBusy
		}
		n.chains[h.TaskID] = &chain{role: target, peer: h.SenderDevice, owner: d.Owner, context: h.ContextID, expiry: h.Expiry,
			recvSeq: 1, recvLast: hashOf(h), sendLast: hashOf(h), reply: next, last: envelope.TypeTask}
		n.mu.Unlock()
	default:
		if next != nil {
			return ErrInner // a caller's follow-up carries no key: our replies go to its reply key
		}
		n.mu.Lock()
		c := n.chains[h.TaskID]
		if c == nil {
			n.mu.Unlock()
			return ErrUnknown
		}
		c.recvSeq, c.recvLast, c.asked, c.hasOwn, c.last = h.Seq+1, hashOf(h), false, false, h.Type // the follow-up key was spent by this message
		if h.Type == envelope.TypeCancel {
			c.cancel = true
		}
		n.mu.Unlock()
	}
	in.Content = content
	n.cfg.OnInbound(in)
	return nil
}

// executeOut runs after a reply to a task we sent was opened.
func (n *Node) executeOut(d receive.Delivered) error {
	h := d.Header
	next, content, err := unpack(d.Plaintext)
	if err != nil {
		return err
	}
	if next != nil {
		if err := n.checkNext(next, h.SenderDevice, nil); err != nil {
			return err
		}
	} else if h.Type == envelope.TypeInputRequired {
		return ErrInner // a question the caller could not answer
	}
	n.mu.Lock()
	c := n.chains[h.TaskID]
	if c == nil {
		n.mu.Unlock()
		return ErrUnknown
	}
	c.recvSeq, c.recvLast, c.last = h.Seq+1, hashOf(h), h.Type
	c.follow = next // nil when the reply carries no key: no follow-up is possible until the next one
	c.input = h.Type == envelope.TypeInputRequired
	if isFinal(h.Type) {
		c.done, c.hasOwn = true, false // the reply key was erased with the last reply
	}
	n.mu.Unlock()
	n.cfg.OnUpdate(Update{Type: h.Type, TaskID: h.TaskID, Content: content})
	return nil
}

// Sweep ends what has run out of time: a task past its expiry without a final
// message is failed (the caller is told), its keys are erased and the chain is
// dropped; a caller's cancel that was never acknowledged erases the reply key
// after CancelWait. Call it every few seconds.
func (n *Node) Sweep() {
	now := n.cfg.Now()
	var expired []Update
	n.mu.Lock()
	for id, c := range n.chains {
		if c.role == caller && c.cancel && !c.done && now.After(c.cancelBy) {
			// Nobody acknowledged the cancel: the reply key goes, and the task is lost.
			n.eraseKey(c)
			c.done = true
			expired = append(expired, Update{Type: envelope.TypeError, TaskID: id, Expired: true})
		}
		if now.Before(c.expiry) {
			continue
		}
		if c.role == caller && !c.done {
			expired = append(expired, Update{Type: envelope.TypeError, TaskID: id, Expired: true})
		}
		n.forget(id, c)
	}
	n.mu.Unlock()
	for _, u := range expired {
		n.cfg.OnUpdate(u)
	}
}

// State is a task's last signed message type on this device, and false when the
// task is unknown (never seen, or past its expiry).
func (n *Node) State(id [16]byte) (envelope.Type, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if c := n.chains[id]; c != nil {
		return c.last, true
	}
	return 0, false
}
