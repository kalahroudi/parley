// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package receive is the daemon's receive path for messages sealed to a
// one-time prekey. It enforces the plan's at-most-once order:
//
//  1. cheap header checks (tenant, target, validity window, prekey id);
//  2. the sender: revocation, root-signed binding, owner allowlist and the
//     transcript signature, all before any ciphertext is opened;
//  3. the replay table (recorded here, taken back if the message never runs);
//  4. AEAD open, with the private key only lent, never consumed;
//  5. erase the private key (Consume);
//  6. acknowledge;
//  7. execute.
//
// The order is structural. Receive is the only code that calls execute, and it
// does so only after Consume and ack have returned nil; Delivered carries an
// unexported field, so no other package can build one and hand it to an
// executor that skips those steps.
//
// Failures. A frame that is not authentic (steps 1 and 2) touches neither the
// replay table nor the prekey, so junk, a wrong sender, a stale binding or a
// bad signature cannot burn a key or fill the table. Once a frame is
// authentic, any failure before step 7 leaves nothing executed, takes the
// replay entry back, and lets the legitimate frame (or a resend) try again;
// the prekey is erased exactly when step 5 succeeds. Plaintext is zeroed on
// every return and on a panic, including a panic in ack or execute. If
// execute fails or panics the replay entry stays: the task may have run.
//
// Restart invariant. The replay table is memory only (internal/replay), which
// is safe only because prekeys are memory only too (internal/prekey). After a
// restart the table is empty, but every private key is gone, so a frame
// captured before the restart can no longer be opened; it fails at step 4 with
// ErrDropped and never reaches the replay table or execute. Anything that
// persisted prekeys would break replay safety and must change both packages
// together. A crash after step 5 loses the task and the caller resends with a
// fresh prekey: plaintext is never persisted to survive it.
//
// Errors are fixed sentinels (optionally wrapping another sentinel); they never
// carry payload, keys, identifiers or the owner. The package writes no logs.
// Errors returned by the caller's own ack and execute pass through unchanged.
// Identifiers are compared in constant time.
package receive

import (
	"crypto/ed25519"
	"crypto/subtle"
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
	// ErrConfig means the receiver was built without a required field.
	ErrConfig = errors.New("receive: incomplete configuration")
	// ErrFault wraps an error a test hook injected at a crash point.
	ErrFault = errors.New("receive: injected fault")
	// ErrAck means the acknowledgment failed; the task was not executed.
	ErrAck = errors.New("receive: acknowledgment failed")
)

// Stage names a point in the receive order, for fault injection.
type Stage uint8

// The stages, in order. Config.Fault is called after each one completes.
const (
	StageAuthenticated Stage = iota + 1 // sender and signature verified, nothing recorded
	StageRecorded                       // replay entry written
	StageOpened                         // plaintext in hand, key still intact
	StageErased                         // key erased, not yet acknowledged
	StageAcked                          // acknowledged, not yet executed
)

// Delivered is what execute gets. Plaintext is zeroed when execute returns, so
// it must not retain the slice. Only this package can construct one.
type Delivered struct {
	Header    envelope.Header
	Owner     string // owner identity from the sender's root-signed binding
	Plaintext []byte

	_ struct{} // unexported: a Delivered exists only after erase and ack
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
	// Fault is a test seam for crash points: a non-nil return aborts the
	// receive right after that stage, as if the process had died there (the
	// caller then builds a fresh pool and table to model the restart). Nil in
	// production.
	Fault func(Stage) error
}

// Receiver is safe for concurrent use.
type Receiver struct{ cfg Config }

// New returns a receiver. All fields except Skew, Now and Fault are required;
// a missing one is an error rather than a nil call on the first frame.
func New(cfg Config) (*Receiver, error) {
	if cfg.Tenant == "" || cfg.Device == "" || cfg.Pool == nil || cfg.Replay == nil || cfg.Lookup == nil ||
		cfg.Bindings == nil || cfg.Revoked == nil || cfg.Allow == nil {
		return nil, ErrConfig
	}
	if cfg.Skew == 0 {
		cfg.Skew = DefaultSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Receiver{cfg: cfg}, nil
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

// eq compares identifiers in constant time.
func eq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (r *Receiver) fault(st Stage) error {
	if r.cfg.Fault == nil {
		return nil
	}
	if err := r.cfg.Fault(st); err != nil {
		return fmt.Errorf("%w: %w", ErrFault, err)
	}
	return nil
}

// Receive runs the receive order on m. ack is called once, after the private
// key is erased and before execute; if it fails, execute is not called.
func (r *Receiver) Receive(m *envelope.Message, ack func() error, execute func(Delivered) error) (err error) {
	if m == nil {
		return ErrNotForUs
	}
	h := m.Header
	id, ok := parseID(h.PrekeyID)
	if !ok || !eq(h.Tenant, r.cfg.Tenant) || !eq(h.TargetDevice, r.cfg.Device) {
		return ErrNotForUs
	}
	now := r.cfg.Now()
	// !Before, not After: replay.Accept refuses expiry == now, so agree here.
	if !now.Before(h.Expiry) || h.IssuedAt.After(now.Add(r.cfg.Skew)) {
		return ErrExpired
	}

	// Authenticate before anything is recorded or opened.
	owner, err := r.authenticate(m)
	if err != nil {
		return err
	}
	if err := r.fault(StageAuthenticated); err != nil {
		return err
	}

	rk := replay.Key{Sender: h.SenderDevice, Task: h.TaskID, Seq: h.Seq}
	if err := r.cfg.Replay.Accept(rk, h.Expiry); err != nil {
		if errors.Is(err, replay.ErrReplay) {
			return fmt.Errorf("%w: %w", ErrDropped, err)
		}
		return fmt.Errorf("%w: %w", ErrRejected, err)
	}
	// Until execute starts, nothing has run, so take the entry back on any
	// error or panic: the resend must not meet our own replay entry.
	started := false
	defer func() {
		if !started {
			r.cfg.Replay.Forget(rk)
		}
	}()
	if err := r.fault(StageRecorded); err != nil {
		return err
	}

	// Open under a loan of the key. An error leaves the key intact.
	var pt []byte
	defer func() { clear(pt) }()
	err = r.cfg.Pool.With(id, func(sk *[32]byte) error {
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
	if err := r.fault(StageOpened); err != nil {
		return err
	}

	// Erase. Exactly one of any concurrent deliveries wins this.
	if err := r.cfg.Pool.Consume(id); err != nil {
		return fmt.Errorf("%w: %w", ErrDropped, err)
	}
	if err := r.fault(StageErased); err != nil {
		return err
	}
	if err := ack(); err != nil {
		return fmt.Errorf("%w: %w", ErrAck, err)
	}
	if err := r.fault(StageAcked); err != nil {
		return err
	}
	started = true
	return execute(Delivered{Header: h, Owner: owner, Plaintext: pt})
}

// authenticate checks the sender and returns the binding's owner. It reads
// the frame but changes nothing of ours.
func (r *Receiver) authenticate(m *envelope.Message) (string, error) {
	h := m.Header
	if eq(h.SenderDevice, r.cfg.Device) || r.cfg.Revoked(h.SenderDevice) {
		return "", ErrRejected
	}
	b, err := r.cfg.Lookup(h.SenderDevice)
	if err != nil || b == nil || !eq(b.Tenant, r.cfg.Tenant) || !eq(b.DeviceID, h.SenderDevice) ||
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
