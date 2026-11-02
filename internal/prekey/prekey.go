// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package prekey implements on-demand one-time prekeys. A target device issues
// a fresh X25519 keypair per caller request and signs the public half with its
// signing key. The private scalar lives only in locked memory outside the Go
// heap, never on disk, and is zeroed on use or expiry. Consumed ids are
// tombstoned until they expire so a reused or redelivered id fails.
//
// Erasure is best effort: crypto/ecdh copies the scalar onto the Go heap while
// it derives the public key or performs a key agreement, and Go offers no
// zeroing guarantee for those copies.
package prekey

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"runtime/debug"
	"sync"
	"time"
)

const (
	// DefaultTTL applies when a request names no task expiry.
	DefaultTTL = 15 * time.Minute
	// MaxTTL caps how long any prekey can live.
	MaxTTL = 24 * time.Hour
	// DefaultSkew is added to the task expiry for clock skew.
	DefaultSkew = 2 * time.Minute
	// DefaultCapacity is how many unused prekeys can be held at once.
	DefaultCapacity = 512
	// DefaultPerCaller is how many unused prekeys one caller device may hold.
	DefaultPerCaller = 8

	scalarSize = 32
	idSize     = 16
	label      = "parley/prekey/v1"
	suiteID    = "x25519-hkdf-sha256-chacha20poly1305"
)

var (
	ErrUnknown     = errors.New("prekey: unknown id")
	ErrConsumed    = errors.New("prekey: already used")
	ErrExpired     = errors.New("prekey: expired")
	ErrRateLimited = errors.New("prekey: caller holds too many unused prekeys")
	ErrPoolFull    = errors.New("prekey: no free slots")
	ErrBadRequest  = errors.New("prekey: request is missing the caller, a nonce or a future expiry")
	ErrBadSig      = errors.New("prekey: signature does not verify")
	ErrMismatch    = errors.New("prekey: field does not match the request or binding")
	ErrClosed      = errors.New("prekey: pool closed")
)

// Prekey is the statement the target signs.
type Prekey struct {
	Tenant         string
	DeviceID       string
	SigningKeyID   string
	BindingVersion uint64
	ID             [idSize]byte
	PublicKey      []byte // X25519, 32 bytes
	CallerDeviceID string
	Nonce          []byte // the caller's request nonce
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// Signed is a prekey with the target's signature over it.
type Signed struct {
	Prekey
	Signature []byte
}

// Encode is the deterministic signed encoding: each field length-prefixed,
// times as unix seconds.
func (p Prekey) Encode() []byte {
	var out []byte
	field := func(b []byte) {
		out = binary.BigEndian.AppendUint32(out, uint32(len(b)))
		out = append(out, b...)
	}
	field([]byte(label))
	field([]byte(suiteID))
	field([]byte(p.Tenant))
	field([]byte(p.DeviceID))
	field([]byte(p.SigningKeyID))
	out = binary.BigEndian.AppendUint64(out, p.BindingVersion)
	field(p.ID[:])
	field(p.PublicKey)
	field([]byte(p.CallerDeviceID))
	field(p.Nonce)
	out = binary.BigEndian.AppendUint64(out, uint64(p.CreatedAt.Unix()))
	out = binary.BigEndian.AppendUint64(out, uint64(p.ExpiresAt.Unix()))
	return out
}

// Request is what a caller asks for. The caller's binding and allowlist are
// checked before Issue is called.
type Request struct {
	Caller     string    // caller device id
	Nonce      []byte    // fresh per request, echoed in the signed prekey
	TaskExpiry time.Time // zero means DefaultTTL from now
}

// Config identifies the issuing device.
type Config struct {
	Tenant         string
	DeviceID       string
	SigningKeyID   string
	BindingVersion uint64
	Signer         ed25519.PrivateKey
	Capacity       int // zero means DefaultCapacity
	PerCaller      int // zero means DefaultPerCaller
	Skew           time.Duration
	Now            func() time.Time // for tests
}

type slot struct {
	index   int
	caller  string
	expires time.Time
}

// Pool holds the unused private prekeys.
type Pool struct {
	cfg  Config
	mem  []byte
	free []int

	mu     sync.Mutex
	live   map[[idSize]byte]slot
	spent  map[[idSize]byte]time.Time // tombstones until expiry
	closed bool
}

// New allocates the locked region. It fails closed if memory cannot be locked.
func New(cfg Config) (*Pool, error) {
	if len(cfg.Signer) != ed25519.PrivateKeySize || cfg.Tenant == "" || cfg.DeviceID == "" {
		return nil, ErrBadRequest
	}
	if cfg.Capacity <= 0 {
		cfg.Capacity = DefaultCapacity
	}
	if cfg.PerCaller <= 0 {
		cfg.PerCaller = DefaultPerCaller
	}
	if cfg.Skew <= 0 {
		cfg.Skew = DefaultSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	mem, err := allocLocked(cfg.Capacity * scalarSize)
	if err != nil {
		return nil, err
	}
	p := &Pool{cfg: cfg, mem: mem, live: map[[idSize]byte]slot{}, spent: map[[idSize]byte]time.Time{}}
	for i := cfg.Capacity - 1; i >= 0; i-- {
		p.free = append(p.free, i)
	}
	return p, nil
}

func (p *Pool) scalar(i int) []byte { return p.mem[i*scalarSize : (i+1)*scalarSize] }

// sweep zeroes expired prekeys and forgets tombstones whose prekey would be
// expired anyway. Caller holds mu.
func (p *Pool) sweep(now time.Time) {
	for id, s := range p.live {
		if !now.Before(s.expires) {
			p.release(id, s)
		}
	}
	for id, exp := range p.spent {
		if !now.Before(exp) {
			delete(p.spent, id)
		}
	}
}

// release zeroes the scalar and tombstones the id until it would have expired.
func (p *Pool) release(id [idSize]byte, s slot) {
	clear(p.scalar(s.index))
	p.free = append(p.free, s.index)
	delete(p.live, id)
	p.spent[id] = s.expires
}

// Issue generates a fresh keypair for the caller and returns the signed public
// half.
func (p *Pool) Issue(req Request) (*Signed, error) {
	if req.Caller == "" || len(req.Nonce) == 0 {
		return nil, ErrBadRequest
	}
	now := p.cfg.Now().UTC().Truncate(time.Second)
	exp := now.Add(DefaultTTL)
	if !req.TaskExpiry.IsZero() {
		if !req.TaskExpiry.After(now) {
			return nil, ErrBadRequest
		}
		exp = req.TaskExpiry.Add(p.cfg.Skew)
	}
	if max := now.Add(MaxTTL); exp.After(max) {
		exp = max
	}
	exp = exp.UTC().Truncate(time.Second)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrClosed
	}
	p.sweep(now)
	held := 0
	for _, s := range p.live {
		if s.caller == req.Caller {
			held++
		}
	}
	if held >= p.cfg.PerCaller {
		return nil, ErrRateLimited
	}
	if len(p.free) == 0 {
		return nil, ErrPoolFull
	}
	i := p.free[len(p.free)-1]
	sc := p.scalar(i)
	if _, err := rand.Read(sc); err != nil {
		clear(sc)
		return nil, err
	}
	// The temporary private key object is a heap copy; see the package note.
	priv, err := ecdh.X25519().NewPrivateKey(sc)
	if err != nil {
		clear(sc)
		return nil, err
	}
	pre := Prekey{
		Tenant: p.cfg.Tenant, DeviceID: p.cfg.DeviceID, SigningKeyID: p.cfg.SigningKeyID,
		BindingVersion: p.cfg.BindingVersion, PublicKey: priv.PublicKey().Bytes(),
		CallerDeviceID: req.Caller, Nonce: bytes.Clone(req.Nonce), CreatedAt: now, ExpiresAt: exp,
	}
	for {
		if _, err := rand.Read(pre.ID[:]); err != nil {
			clear(sc)
			return nil, err
		}
		_, a := p.live[pre.ID]
		_, b := p.spent[pre.ID]
		if !a && !b {
			break
		}
	}
	p.free = p.free[:len(p.free)-1]
	p.live[pre.ID] = slot{index: i, caller: req.Caller, expires: exp}
	return &Signed{Prekey: pre, Signature: ed25519.Sign(p.cfg.Signer, pre.Encode())}, nil
}

// With lends the private scalar to fn without consuming it, so the caller can
// attempt the AEAD open. Junk frames that fail to open leave the key intact.
// fn must not retain the slice. Call Consume once the open succeeds.
func (p *Pool) With(id [idSize]byte, fn func(scalar []byte) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, err := p.lookup(id)
	if err != nil {
		return err
	}
	return fn(p.scalar(s.index))
}

// Consume zeroes the private key and tombstones the id, so a second use fails.
func (p *Pool) Consume(id [idSize]byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, err := p.lookup(id)
	if err != nil {
		return err
	}
	p.release(id, s)
	return nil
}

func (p *Pool) lookup(id [idSize]byte) (slot, error) {
	if p.closed {
		return slot{}, ErrClosed
	}
	p.sweep(p.cfg.Now())
	if s, ok := p.live[id]; ok {
		return s, nil
	}
	if _, ok := p.spent[id]; ok {
		return slot{}, ErrConsumed
	}
	return slot{}, ErrUnknown
}

// Outstanding is the number of unused prekeys held.
func (p *Pool) Outstanding() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweep(p.cfg.Now())
	return len(p.live)
}

// Close zeroes and unmaps every key.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	freeLocked(p.mem)
	p.live = nil
}

// Expect is what the caller knows about the prekey it asked for.
type Expect struct {
	Tenant         string
	DeviceID       string // the target
	Caller         string // this caller's device id
	Nonce          []byte // the nonce sent in the request
	BindingVersion uint64 // from the target's verified binding
	Now            time.Time
	Skew           time.Duration // zero means DefaultSkew
}

// Verify checks a signed prekey against the target's signing key (taken from
// its root-signed binding) and the caller's own request.
func Verify(signingKey ed25519.PublicKey, s *Signed, e Expect) error {
	if len(signingKey) != ed25519.PublicKeySize || len(s.PublicKey) != scalarSize ||
		!ed25519.Verify(signingKey, s.Encode(), s.Signature) {
		return ErrBadSig
	}
	if s.Tenant != e.Tenant || s.DeviceID != e.DeviceID || s.CallerDeviceID != e.Caller ||
		!bytes.Equal(s.Nonce, e.Nonce) || s.BindingVersion != e.BindingVersion {
		return ErrMismatch
	}
	skew := e.Skew
	if skew <= 0 {
		skew = DefaultSkew
	}
	if e.Now.Add(skew).Before(s.CreatedAt) || !s.ExpiresAt.After(s.CreatedAt) {
		return ErrMismatch
	}
	if !e.Now.Before(s.ExpiresAt) {
		return ErrExpired
	}
	return nil
}

// Harden disables core dumps and Go tracebacks for this process. Call it once
// at daemon start.
func Harden() error {
	debug.SetTraceback("none")
	return disableCoreDumps()
}
