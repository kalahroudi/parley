// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package binding implements root-signed device bindings: the tenant signing
// root vouches for {tenant, owner, device id, signing public key, version,
// not_after}. Daemons pin only the root public key and reject bindings that
// are forged, expired or older than one they have already seen.
package binding

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// Lifetime is how long a freshly signed binding stays valid.
const Lifetime = 90 * 24 * time.Hour

const label = "parley/binding/v1"

var (
	ErrBadSignature = errors.New("binding: signature does not verify against the pinned root")
	ErrExpired      = errors.New("binding: expired")
	ErrRollback     = errors.New("binding: version lower than one already seen")
	ErrInvalid      = errors.New("binding: missing or malformed field")
	ErrConflict     = errors.New("binding: different binding at a version already seen")
)

// Binding is the statement the root signs. Encryption keys are not part of it:
// task encryption uses one-time prekeys.
type Binding struct {
	Tenant     string            `json:"tenant"`
	Owner      string            `json:"owner"` // user email or named service owner
	DeviceID   string            `json:"device_id"`
	SigningKey ed25519.PublicKey `json:"signing_key"`
	Version    uint64            `json:"version"`
	NotAfter   time.Time         `json:"not_after"`
}

// Signed is a binding together with the root's signature over it.
type Signed struct {
	Binding
	Signature []byte `json:"signature"`
}

func (b Binding) validate() error {
	if b.Tenant == "" || b.Owner == "" || b.DeviceID == "" || b.Version == 0 ||
		len(b.SigningKey) != ed25519.PublicKeySize || b.NotAfter.IsZero() {
		return ErrInvalid
	}
	return nil
}

// Encode is the deterministic signed encoding: a label, then each field
// length-prefixed (so no field boundary is ambiguous), with not_after as unix
// seconds.
func (b Binding) Encode() []byte {
	var out []byte
	field := func(p []byte) {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	field([]byte(label))
	field([]byte(b.Tenant))
	field([]byte(b.Owner))
	field([]byte(b.DeviceID))
	field(b.SigningKey)
	out = binary.BigEndian.AppendUint64(out, b.Version)
	out = binary.BigEndian.AppendUint64(out, uint64(b.NotAfter.Unix()))
	return out
}

// Sign signs b with the root key. NotAfter is truncated to whole seconds.
func Sign(root ed25519.PrivateKey, b Binding) (*Signed, error) {
	b.NotAfter = b.NotAfter.UTC().Truncate(time.Second)
	if err := b.validate(); err != nil {
		return nil, err
	}
	return &Signed{Binding: b, Signature: ed25519.Sign(root, b.Encode())}, nil
}

// Verify checks the signature against the pinned root key and that the binding
// is valid at now. It does not check versions; see Tracker.
func Verify(root ed25519.PublicKey, s *Signed, now time.Time) error {
	if s == nil || len(root) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	if err := s.validate(); err != nil {
		return err
	}
	if !ed25519.Verify(root, s.Encode(), s.Signature) {
		return ErrBadSignature
	}
	// The signature covers whole seconds only, so ignore any sub-second extension.
	if !now.Before(s.NotAfter.Truncate(time.Second)) {
		return ErrExpired
	}
	return nil
}

// Tracker remembers the highest binding version seen per device and rejects
// anything lower, so an old (possibly compromised-key) binding cannot be replayed.
// With a Store the state survives restarts.
type Tracker struct {
	root  ed25519.PublicKey
	store Store
	mu    sync.Mutex
	seen  map[deviceKey]Record
}

type deviceKey struct{ tenant, device string }

// NewTracker pins the root public key and loads previously saved state from
// store. A nil store keeps state in memory only. It fails if the store cannot
// be read or is corrupt; callers must not fall back to an empty state.
func NewTracker(root ed25519.PublicKey, store Store) (*Tracker, error) {
	t := &Tracker{root: root, store: store, seen: map[deviceKey]Record{}}
	if store != nil {
		recs, err := store.Load()
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			t.seen[deviceKey{r.Tenant, r.DeviceID}] = r
		}
	}
	return t, nil
}

// Version is the highest binding version this tracker has recorded for the
// device, and false when it has recorded none.
func (t *Tracker) Version(tenant, device string) (uint64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.seen[deviceKey{tenant, device}]
	return r.Version, ok
}

// Accept verifies s, durably records its version, and only then returns nil.
// The identical binding can be presented repeatedly; a different binding at the
// same version is rejected. If the store cannot be written, s is rejected.
func (t *Tracker) Accept(s *Signed, now time.Time) error {
	if err := Verify(t.root, s, now); err != nil {
		return err
	}
	k := deviceKey{s.Tenant, s.DeviceID}
	rec := Record{Tenant: s.Tenant, DeviceID: s.DeviceID, Version: s.Version, Encoded: s.Encode()}
	t.mu.Lock()
	defer t.mu.Unlock()
	if l, ok := t.store.(Locker); ok {
		// Another process may have recorded bindings since we last looked: hold
		// the store lock and re-read before judging and writing, so its records
		// are neither missed nor overwritten.
		release, err := l.Lock()
		if err != nil {
			return err
		}
		defer release()
		recs, err := t.store.Load()
		if err != nil {
			return err
		}
		t.seen = make(map[deviceKey]Record, len(recs))
		for _, r := range recs {
			t.seen[deviceKey{r.Tenant, r.DeviceID}] = r
		}
	}
	if v, ok := t.seen[k]; ok {
		if s.Version < v.Version {
			return ErrRollback
		}
		if s.Version == v.Version {
			if !bytes.Equal(rec.Encoded, v.Encoded) {
				return ErrConflict
			}
			return nil // already recorded
		}
	}
	if t.store != nil {
		recs := make([]Record, 0, len(t.seen)+1)
		for kk, r := range t.seen {
			if kk != k {
				recs = append(recs, r)
			}
		}
		if err := t.store.Save(append(recs, rec)); err != nil {
			return err
		}
	}
	t.seen[k] = rec
	return nil
}
