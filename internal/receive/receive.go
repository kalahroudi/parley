// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package receive is the daemon's receive path for messages sealed to a
// one-time prekey. It enforces the plan's at-most-once order:
//
//  1. cheap header checks (tenant, target, validity window, prekey id);
//  2. AEAD open, with the private key only lent, never consumed, so a junk
//     frame cannot burn it;
//  3. the sender's root-signed binding, revocation status, owner allowlist and
//     transcript signature, then the replay table;
//  4. erase the private key (Consume);
//  5. acknowledge;
//  6. execute.
//
// A failure at steps 1 to 3 leaves the prekey usable; the legitimate sender's
// frame can still arrive. A crash after step 4 loses the task and the caller
// resends with a fresh prekey: plaintext is never persisted to survive it.
// A redelivered frame for a consumed prekey id is dropped (ErrDropped).
//
// Errors are fixed sentinels (optionally wrapping another sentinel); they never
// carry payload, keys or identifiers.
package receive

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/replay"
)

// DefaultSkew is how far in the future a message's issued-at may be.
const DefaultSkew = 2 * time.Minute

var (
	// ErrNotForUs means the header names another tenant, device or a malformed
	// prekey id.
	ErrNotForUs = errors.New("receive: message is not addressed to this device")
	// ErrExpired means the message is outside its signed validity window.
	ErrExpired = errors.New("receive: message outside its validity window")
	// ErrDropped means a redelivery or replay of a message already accepted, or
	// a prekey that is gone. Drop silently; nothing was executed.
	ErrDropped = errors.New("receive: redelivered or unknown prekey, dropped")
	// ErrRejected means the sender failed binding, revocation, allowlist,
	// signature or replay-table checks. The prekey is still intact.
	ErrRejected = errors.New("receive: sender not accepted")
	// ErrAck means the acknowledgment failed; the task was not executed.
	ErrAck = errors.New("receive: acknowledgment failed")
)

// Delivered is what execute gets. Plaintext is zeroed when execute returns, so
// it must not retain the slice.
type Delivered struct {
	Header    envelope.Header
	Owner     string // owner identity from the sender's root-signed binding
	Plaintext []byte
}

// Config wires the receiver to the device's own state.
type Config struct {
	Tenant string
	Device string
	Pool   *prekey.Pool
	Replay *replay.Table
	// Lookup returns the sender's current root-signed binding.
	Lookup func(device string) (*binding.Signed, error)
	// Bindings verifies the root signature and records the version, so a
	// rolled-back binding is refused.
	Bindings *binding.Tracker
	// Revoked reports whether the signed revocation list revokes the device
	// (revocation.Guard.IsRevoked: it still denies when the list is stale).
	Revoked func(device string) bool
	// Allow is the owner's allowlist, evaluated on the binding's owner.
	Allow func(owner string) bool
	Skew  time.Duration    // zero means DefaultSkew
	Now   func() time.Time // nil means time.Now
}

// Receiver is safe for concurrent use.
type Receiver struct{ cfg Config }

// New returns a receiver. All fields except Skew and Now are required.
func New(cfg Config) *Receiver {
	if cfg.Skew == 0 {
		cfg.Skew = DefaultSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Receiver{cfg: cfg}
}

// PrekeyID is the string form of a prekey id carried in Header.PrekeyID.
func PrekeyID(id [16]byte) string { return hex.EncodeToString(id[:]) }

func parseID(s string) (id [16]byte, ok bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, false
	}
	copy(id[:], b)
	return id, true
}

// Receive runs the receive order on m. ack is called once, after the private
// key is erased and before execute; if it fails, execute is not called.
func (r *Receiver) Receive(m *envelope.Message, ack func() error, execute func(Delivered) error) error {
	h := m.Header
	id, ok := parseID(h.PrekeyID)
	if !ok || h.Tenant != r.cfg.Tenant || h.TargetDevice != r.cfg.Device {
		return ErrNotForUs
	}
	now := r.cfg.Now()
	if now.After(h.Expiry) || h.IssuedAt.After(now.Add(r.cfg.Skew)) {
		return ErrExpired
	}

	// Open under a loan of the key. An error leaves the key intact.
	var pt []byte
	err := r.cfg.Pool.With(id, func(sk *[32]byte) error {
		var oerr error
		pt, oerr = m.Open(sk[:])
		return oerr
	})
	if err != nil {
		switch {
		case errors.Is(err, prekey.ErrUnknown), errors.Is(err, prekey.ErrConsumed), errors.Is(err, prekey.ErrClosed):
			return fmt.Errorf("%w: %w", ErrDropped, err)
		case errors.Is(err, prekey.ErrExpired):
			return fmt.Errorf("%w: %w", ErrExpired, err)
		}
		return err // envelope.ErrOpen or ErrInvalid
	}
	defer clear(pt)

	owner, err := r.authenticate(m)
	if err != nil {
		return err
	}
	if err := r.cfg.Replay.Accept(replay.Key{Sender: h.SenderDevice, Task: h.TaskID, Seq: h.Seq}, h.Expiry); err != nil {
		if errors.Is(err, replay.ErrReplay) {
			return fmt.Errorf("%w: %w", ErrDropped, err)
		}
		return fmt.Errorf("%w: %w", ErrRejected, err)
	}

	// Erase. Exactly one of any concurrent deliveries wins this.
	if err := r.cfg.Pool.Consume(id); err != nil {
		return fmt.Errorf("%w: %w", ErrDropped, err)
	}
	if err := ack(); err != nil {
		return fmt.Errorf("%w: %w", ErrAck, err)
	}
	return execute(Delivered{Header: h, Owner: owner, Plaintext: pt})
}

// authenticate checks the sender and returns the binding's owner.
func (r *Receiver) authenticate(m *envelope.Message) (string, error) {
	h := m.Header
	if h.SenderDevice == r.cfg.Device || r.cfg.Revoked(h.SenderDevice) {
		return "", ErrRejected
	}
	b, err := r.cfg.Lookup(h.SenderDevice)
	if err != nil || b == nil || b.Tenant != r.cfg.Tenant || b.DeviceID != h.SenderDevice ||
		b.Version != h.BindingVersion {
		return "", ErrRejected
	}
	if err := r.cfg.Bindings.Accept(b, r.cfg.Now()); err != nil {
		return "", fmt.Errorf("%w: %w", ErrRejected, err)
	}
	if !r.cfg.Allow(b.Owner) {
		return "", ErrRejected
	}
	if err := m.Verify(ed25519.PublicKey(b.SigningKey)); err != nil {
		return "", fmt.Errorf("%w: %w", ErrRejected, err)
	}
	return b.Owner, nil
}
