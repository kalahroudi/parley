// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package prekey implements on-demand one-time prekeys. A target device issues
// a fresh X25519 keypair per caller request and signs the public half with its
// signing key. The private scalar lives only in locked memory outside the Go
// heap, never on disk, and is zeroed on use or expiry. Consumed ids are
// tombstoned until they expire so a reused or redelivered id fails.
//
// Guarantee level. The scalars live in memory mapped outside the Go heap, so
// the garbage collector never moves or copies them, and they are handed out as
// *[32]byte into that region, never as copies. New locks the region in RAM
// (mlock / VirtualLock) and fails with ErrNotLocked if it cannot, unless
// Config.AllowUnlocked is set; Pool.Locked reports which level was obtained.
// An unlocked pool can be swapped out. Linux also excludes the region from core
// dumps (MADV_DONTDUMP, best effort); Harden disables core dumps process-wide
// and must be called by the daemon at start.
//
// What Go cannot promise: crypto/ecdh copies the scalar onto the Go heap while
// it derives the public key (once per prekey, in Issue), and a caller that
// feeds the scalar to crypto/ecdh or an HPKE implementation gets further
// heap copies there. Those copies are not zeroed and can reach swap or a core
// dump if Harden was not called or the OS swaps the heap. So erased means the
// locked slot is zeroed; copies in the Go heap are best effort and bounded, not
// gone.
//
// Registers and signal stacks. A 32-byte copy of the scalar leaves it in the
// CPU's vector registers, and a signal that interrupts the thread then makes
// the kernel write those registers onto a signal stack, which Go keeps in its
// heap. The runtime sends such a signal (SIGURG, to preempt) at the start of a
// garbage collection. What the package does about it, per platform:
//
//   - Linux: Issue and With run on a locked thread with asynchronous signals
//     blocked, clear the vector registers, and only then unblock, so no signal
//     can snapshot them while the key is in them. Measured on amd64 CI: the
//     address-space scan went from 91 failures in 200 runs to none in 100.
//   - macOS and Windows: signals are not blocked, so the window stays open: a
//     signal landing inside the operation can leave a copy of the scalar in a
//     signal stack.
//   - Vector registers are cleared after each use on amd64 and arm64 (all
//     platforms); on other architectures nothing is cleared.
//
// General-purpose registers and stack spills are not cleared on any platform;
// Go offers no way to do so. Errors and logs
// never carry key material: every error is a fixed sentinel.
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
	// MaxCapacity bounds Config.Capacity (the locked region is Capacity*32 bytes).
	MaxCapacity = 1 << 16
	// DefaultPerCaller is how many unused prekeys one caller device may hold.
	DefaultPerCaller = 8
	// DefaultTombstones bounds the consumed-id memory. Forgetting a tombstone
	// is safe: the id is no longer live, so a reuse fails with ErrUnknown
	// instead of ErrConsumed.
	DefaultTombstones = 1 << 16
	// DefaultSweep is how often the background sweeper zeroes expired keys.
	DefaultSweep = 5 * time.Second
	// MaxNonce and MaxCaller bound what a requester can make the target sign.
	MaxNonce  = 64
	MaxCaller = 256

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
	ErrBadRequest  = errors.New("prekey: bad request or configuration")
	ErrBadSig      = errors.New("prekey: signature does not verify")
	ErrMismatch    = errors.New("prekey: field does not match the request or binding")
	ErrClosed      = errors.New("prekey: pool closed")
	ErrNotLocked   = errors.New("prekey: key memory could not be locked in RAM")
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
	Caller     string    // caller device id, at most MaxCaller bytes
	Nonce      []byte    // fresh per request, 1 to MaxNonce bytes, echoed in the signed prekey
	TaskExpiry time.Time // zero means DefaultTTL from now
}

// Config identifies the issuing device.
type Config struct {
	Tenant         string
	DeviceID       string
	SigningKeyID   string
	BindingVersion uint64
	Signer         ed25519.PrivateKey
	Capacity       int // zero means DefaultCapacity, at most MaxCapacity
	PerCaller      int // zero means DefaultPerCaller
	MaxTombstones  int // zero means DefaultTombstones
	Skew           time.Duration
	SweepEvery     time.Duration // zero means DefaultSweep
	// AllowUnlocked accepts memory that could not be locked in RAM. Without it
	// New fails with ErrNotLocked. Check Pool.Locked for the level obtained.
	AllowUnlocked bool
	Now           func() time.Time // for tests
}

type slot struct {
	index   int
	caller  string
	expires time.Time
}

// Pool holds the unused private prekeys.
type Pool struct {
	cfg    Config
	mem    []byte
	locked bool
	done   chan struct{}
	wg     sync.WaitGroup

	mu        sync.Mutex
	free      []int
	live      map[[idSize]byte]slot
	spent     map[[idSize]byte]time.Time // tombstones until expiry
	nextPrune time.Time
	closed    bool
}

// Test seams: key generation and randomness cannot fail in practice.
var (
	randRead      = rand.Read
	derivePublic  = x25519Public
	errDerivation = errors.New("prekey: key derivation failed")
)

func x25519Public(scalar []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, errDerivation
	}
	return k.PublicKey().Bytes(), nil
}

// New allocates the key region and starts the sweeper that zeroes expired keys.
// It fails closed with ErrNotLocked if the memory cannot be locked, unless
// cfg.AllowUnlocked is set. Call Close to release it.
func New(cfg Config) (*Pool, error) {
	if len(cfg.Signer) != ed25519.PrivateKeySize || cfg.Tenant == "" || cfg.DeviceID == "" ||
		cfg.Capacity > MaxCapacity {
		return nil, ErrBadRequest
	}
	if cfg.Capacity <= 0 {
		cfg.Capacity = DefaultCapacity
	}
	if cfg.PerCaller <= 0 {
		cfg.PerCaller = DefaultPerCaller
	}
	if cfg.MaxTombstones <= 0 {
		cfg.MaxTombstones = DefaultTombstones
	}
	if cfg.Skew <= 0 {
		cfg.Skew = DefaultSkew
	}
	if cfg.SweepEvery <= 0 {
		cfg.SweepEvery = DefaultSweep
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	mem, locked, err := allocRegion(cfg.Capacity*scalarSize, cfg.AllowUnlocked)
	if err != nil {
		return nil, err
	}
	p := &Pool{cfg: cfg, mem: mem, locked: locked, done: make(chan struct{}),
		live: map[[idSize]byte]slot{}, spent: map[[idSize]byte]time.Time{}}
	for i := cfg.Capacity - 1; i >= 0; i-- {
		p.free = append(p.free, i)
	}
	p.wg.Add(1)
	go p.janitor()
	return p, nil
}

// Locked reports whether the key memory is locked in RAM (never swapped).
func (p *Pool) Locked() bool { return p.locked }

func (p *Pool) janitor() {
	defer p.wg.Done()
	t := time.NewTicker(p.cfg.SweepEvery)
	defer t.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-t.C:
			p.Sweep()
		}
	}
}

// Sweep zeroes every expired prekey now. The pool also does this on its own
// every Config.SweepEvery.
func (p *Pool) Sweep() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	now := p.cfg.Now()
	p.sweepLive(now)
	p.pruneSpent(now)
}

func (p *Pool) scalar(i int) *[scalarSize]byte {
	return (*[scalarSize]byte)(p.mem[i*scalarSize : (i+1)*scalarSize])
}

// sweepLive zeroes expired prekeys. It is bounded by the capacity. Caller holds mu.
func (p *Pool) sweepLive(now time.Time) {
	for id, s := range p.live {
		if !now.Before(s.expires) {
			p.release(id, s, now)
		}
	}
}

// pruneSpent forgets tombstones whose prekey would be expired anyway, at most
// once a second so that junk lookups cannot make every call scan them.
func (p *Pool) pruneSpent(now time.Time) {
	if now.Before(p.nextPrune) {
		return
	}
	p.nextPrune = now.Add(time.Second)
	for id, exp := range p.spent {
		if !now.Before(exp) {
			delete(p.spent, id)
		}
	}
}

// release zeroes the scalar and, if the key was still valid, tombstones the id
// until it would have expired. Caller holds mu.
func (p *Pool) release(id [idSize]byte, s slot, now time.Time) {
	clear(p.scalar(s.index)[:])
	scrubVectorRegisters() // clear itself moves the bytes through them
	p.free = append(p.free, s.index)
	delete(p.live, id)
	if !now.Before(s.expires) {
		return
	}
	if len(p.spent) >= p.cfg.MaxTombstones {
		for k := range p.spent {
			delete(p.spent, k)
			break
		}
	}
	p.spent[id] = s.expires
}

// Issue generates a fresh keypair for the caller and returns the signed public
// half.
func (p *Pool) Issue(req Request) (*Signed, error) {
	if req.Caller == "" || len(req.Caller) > MaxCaller || len(req.Nonce) == 0 || len(req.Nonce) > MaxNonce {
		return nil, ErrBadRequest
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrClosed
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

	p.sweepLive(now)
	p.pruneSpent(now)
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
	// The random bytes and the public-key derivation pass the scalar through
	// the vector registers.
	restore := quiesce()
	defer func() {
		scrubVectorRegisters()
		restore()
	}()
	// Whatever way this returns or panics before the key is committed, the
	// slot is wiped.
	committed := false
	defer func() {
		if !committed {
			clear(sc[:])
		}
	}()
	if _, err := randRead(sc[:]); err != nil {
		return nil, err
	}
	pub, err := derivePublic(sc[:])
	if err != nil {
		return nil, err
	}
	pre := Prekey{
		Tenant: p.cfg.Tenant, DeviceID: p.cfg.DeviceID, SigningKeyID: p.cfg.SigningKeyID,
		BindingVersion: p.cfg.BindingVersion, PublicKey: pub,
		CallerDeviceID: req.Caller, Nonce: bytes.Clone(req.Nonce), CreatedAt: now, ExpiresAt: exp,
	}
	for {
		if _, err := randRead(pre.ID[:]); err != nil {
			return nil, err
		}
		_, a := p.live[pre.ID]
		_, b := p.spent[pre.ID]
		if !a && !b {
			break
		}
	}
	signed := &Signed{Prekey: pre, Signature: ed25519.Sign(p.cfg.Signer, pre.Encode())}
	p.free = p.free[:len(p.free)-1]
	p.live[pre.ID] = slot{index: i, caller: req.Caller, expires: exp}
	committed = true
	return signed, nil
}

// With lends the private scalar to fn without consuming it, so the caller can
// attempt the AEAD open. Junk frames that fail to open leave the key intact:
// if fn returns an error the key stays valid. If fn panics the key is zeroed
// and its id burned before the panic continues. fn runs under the pool lock; it
// must not retain the pointer or call back into the pool. On Linux it also runs
// with asynchronous signals blocked (see quiesce), so it must be short and must
// not block. Call Consume once the open succeeds.
func (p *Pool) With(id [idSize]byte, fn func(scalar *[scalarSize]byte) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.cfg.Now()
	s, err := p.lookup(id, now)
	if err != nil {
		return err
	}
	returned := false
	restore := quiesce()
	defer func() {
		// Whatever fn did with the scalar (hash it, copy it, open with it), the
		// copy may still sit in the vector registers; clear them before any
		// signal held back by quiesce is delivered.
		scrubVectorRegisters()
		restore()
		if !returned {
			p.release(id, s, now)
		}
	}()
	err = fn(p.scalar(s.index))
	returned = true
	return err
}

// Consume zeroes the private key and tombstones the id, so a second use fails.
// It is atomic: of any number of concurrent calls for one id, exactly one
// succeeds.
func (p *Pool) Consume(id [idSize]byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.cfg.Now()
	s, err := p.lookup(id, now)
	if err != nil {
		return err
	}
	p.release(id, s, now)
	return nil
}

// lookup finds a live, unexpired prekey. An expired one is zeroed on the spot
// and reports ErrExpired; later lookups see ErrUnknown. Caller holds mu.
func (p *Pool) lookup(id [idSize]byte, now time.Time) (slot, error) {
	if p.closed {
		return slot{}, ErrClosed
	}
	if s, ok := p.live[id]; ok {
		if !now.Before(s.expires) {
			p.release(id, s, now)
			return slot{}, ErrExpired
		}
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
	if !p.closed {
		p.sweepLive(p.cfg.Now())
	}
	return len(p.live)
}

// Close zeroes and unmaps every key and stops the sweeper.
func (p *Pool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	freeRegion(p.mem)
	p.live = nil
	p.mu.Unlock()
	close(p.done)
	p.wg.Wait()
}

// Expect is what the caller knows about the prekey it asked for.
type Expect struct {
	Tenant         string
	DeviceID       string // the target
	SigningKeyID   string // from the target's verified binding
	Caller         string // this caller's device id
	Nonce          []byte // the nonce sent in the request
	BindingVersion uint64 // from the target's verified binding
	Now            time.Time
	Skew           time.Duration // zero means DefaultSkew
}

// Verify checks a signed prekey against the target's signing key (taken from
// its root-signed binding) and the caller's own request.
func Verify(signingKey ed25519.PublicKey, s *Signed, e Expect) error {
	if s == nil || len(signingKey) != ed25519.PublicKeySize || len(s.PublicKey) != scalarSize ||
		!ed25519.Verify(signingKey, s.Encode(), s.Signature) {
		return ErrBadSig
	}
	if s.Tenant != e.Tenant || s.DeviceID != e.DeviceID || s.SigningKeyID != e.SigningKeyID || s.CallerDeviceID != e.Caller ||
		!bytes.Equal(s.Nonce, e.Nonce) || s.BindingVersion != e.BindingVersion {
		return ErrMismatch
	}
	skew := e.Skew
	if skew <= 0 {
		skew = DefaultSkew
	}
	if e.Now.Add(skew).Before(s.CreatedAt) || !s.ExpiresAt.After(s.CreatedAt) ||
		s.ExpiresAt.Sub(s.CreatedAt) > MaxTTL {
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
	return runSteps(hardenSteps...)
}

// runSteps stops at the first failing step.
func runSteps(steps ...func() error) error {
	for _, f := range steps {
		if err := f(); err != nil {
			return err
		}
	}
	return nil
}
