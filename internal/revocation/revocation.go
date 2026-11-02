// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package revocation implements the root-signed revocation list. The root
// holder's daemon signs a versioned, timestamped list of revoked device ids and
// re-signs it at least weekly. Every daemon pins the root public key, rejects a
// list that is forged or older than one it has seen, warns when its list is
// more than 7 days old and refuses to send once it is more than 14 days old.
package revocation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"slices"
	"sync"
	"time"
)

const (
	// WarnAfter is the age at which daemons warn that the list is stale.
	WarnAfter = 7 * 24 * time.Hour
	// RefuseAfter is the age beyond which daemons refuse to send.
	RefuseAfter = 14 * 24 * time.Hour
	// RefreshEvery is how often the root holder's daemon re-signs the list.
	RefreshEvery = 24 * time.Hour
	// MaxSkew is how far in the future a list's timestamp may be.
	MaxSkew = 5 * time.Minute
)

const label = "parley/revocation/v1"

var (
	ErrBadSignature = errors.New("revocation: signature does not verify against the pinned root")
	ErrInvalid      = errors.New("revocation: missing or malformed field")
	ErrFuture       = errors.New("revocation: issued in the future")
	ErrRollback     = errors.New("revocation: version lower than one already seen")
	ErrOlder        = errors.New("revocation: issued before the list already held")
	ErrConflict     = errors.New("revocation: different list at a version already seen")
	ErrTenant       = errors.New("revocation: list is for a different tenant")
	ErrNoList       = errors.New("revocation: no list yet; cannot confirm the device is not revoked")
	ErrStale        = errors.New("revocation: list older than 14 days; refusing to send until it refreshes")
	ErrRevoked      = errors.New("revocation: device is revoked")
)

// List is the statement the root signs. Revoked is kept sorted and unique.
type List struct {
	Tenant   string    `json:"tenant"`
	Version  uint64    `json:"version"`
	IssuedAt time.Time `json:"issued_at"`
	Revoked  []string  `json:"revoked"` // device ids
}

// Signed is a list together with the root's signature over it.
type Signed struct {
	List
	Signature []byte `json:"signature"`
}

func (s *Signed) clone() *Signed {
	c := *s
	c.Revoked = slices.Clone(s.Revoked)
	c.Signature = slices.Clone(s.Signature)
	return &c
}

func (l List) validate() error {
	if l.Tenant == "" || l.Version == 0 || l.IssuedAt.IsZero() {
		return ErrInvalid
	}
	for i, id := range l.Revoked {
		if id == "" || (i > 0 && l.Revoked[i-1] >= id) {
			return ErrInvalid // empty, unsorted or duplicate
		}
	}
	return nil
}

// Encode is the deterministic signed encoding: a label, then each field
// length-prefixed, with issued_at as unix seconds.
func (l List) Encode() []byte {
	var out []byte
	field := func(p []byte) {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	field([]byte(label))
	field([]byte(l.Tenant))
	out = binary.BigEndian.AppendUint64(out, l.Version)
	out = binary.BigEndian.AppendUint64(out, uint64(l.IssuedAt.Unix()))
	out = binary.BigEndian.AppendUint32(out, uint32(len(l.Revoked)))
	for _, id := range l.Revoked {
		field([]byte(id))
	}
	return out
}

// Sign signs l with the root key. Revoked is sorted and de-duplicated and
// IssuedAt truncated to whole seconds.
func Sign(root ed25519.PrivateKey, l List) (*Signed, error) {
	l.IssuedAt = l.IssuedAt.UTC().Truncate(time.Second)
	l.Revoked = slices.Compact(slices.Sorted(slices.Values(l.Revoked)))
	if err := l.validate(); err != nil {
		return nil, err
	}
	return &Signed{List: l, Signature: ed25519.Sign(root, l.Encode())}, nil
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// Next signs the successor of prev (nil for the first list): version+1, issued
// now, with add revoked on top of what prev already revoked. Called with no
// additions it is the periodic refresh. Revocation is permanent: a revoked
// device is re-admitted only by enrolling under a new device id.
func Next(root ed25519.PrivateKey, tenant string, prev *Signed, add []string, now time.Time) (*Signed, error) {
	l := List{Tenant: tenant, Version: 1, IssuedAt: now, Revoked: slices.Clone(add)}
	if prev != nil {
		if prev.Tenant != tenant {
			return nil, ErrTenant
		}
		l.Version = prev.Version + 1
		l.IssuedAt = laterOf(now, prev.IssuedAt) // never step back, even if the clock did
		l.Revoked = append(l.Revoked, prev.Revoked...)
	}
	return Sign(root, l)
}

// Verify checks the signature against the pinned root key. It does not check
// versions or age; see Guard.
func Verify(root ed25519.PublicKey, s *Signed, now time.Time) error {
	if err := verifySignature(root, s); err != nil {
		return err
	}
	if s.IssuedAt.Truncate(time.Second).After(now.Add(MaxSkew)) {
		return ErrFuture
	}
	return nil
}

func verifySignature(root ed25519.PublicKey, s *Signed) error {
	if s == nil || len(root) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	if err := s.validate(); err != nil {
		return err
	}
	if !ed25519.Verify(root, s.Encode(), s.Signature) {
		return ErrBadSignature
	}
	return nil
}

// Store persists the newest accepted list so a restart cannot be rolled back
// to an older (shorter) list. Save must be durable before it returns nil.
type Store interface {
	// Load returns the saved list, or nil if none was ever saved.
	Load() (*Signed, error)
	Save(*Signed) error
}

// Status describes how fresh the held list is.
type Status struct {
	Version uint64
	Age     time.Duration
	Warn    bool // older than WarnAfter: tell the user
	Stale   bool // older than RefuseAfter: sends are refused
}

// Guard holds the newest accepted list for one tenant and answers "may I send
// to this device?". It fails closed: no list, or a stale one, means no sends.
type Guard struct {
	root   ed25519.PublicKey
	tenant string
	store  Store
	mu     sync.Mutex
	cur    *Signed
	set    map[string]struct{}
}

// NewGuard pins the root key and tenant and loads any saved list, re-verifying
// it. It fails if the store is unreadable or holds a list that does not verify;
// callers must not fall back to an empty state.
func NewGuard(root ed25519.PublicKey, tenant string, store Store, _ time.Time) (*Guard, error) {
	g := &Guard{root: root, tenant: tenant, store: store}
	if store == nil {
		return g, nil
	}
	s, err := store.Load()
	if err != nil {
		return nil, err
	}
	if s != nil {
		// The skew check was applied when the list was first accepted; a
		// clock set back since must not stop the daemon from starting.
		if err := verifySignature(root, s); err != nil {
			return nil, err
		}
		if s.Tenant != tenant {
			return nil, ErrTenant
		}
		g.adopt(s.clone())
	}
	return g, nil
}

func (g *Guard) check(s *Signed, now time.Time) error {
	if err := Verify(g.root, s, now); err != nil {
		return err
	}
	if s.Tenant != g.tenant {
		return ErrTenant
	}
	return nil
}

func (g *Guard) adopt(s *Signed) {
	g.cur = s
	g.set = make(map[string]struct{}, len(s.Revoked))
	for _, id := range s.Revoked {
		g.set[id] = struct{}{}
	}
}

// Accept verifies s, durably records it, and only then switches to it. A lower
// version is rejected; the identical list may be presented again; a different
// list at the same version is rejected, as is a higher version issued before
// the held list (a root clock that went backwards must not shorten the list's
// apparent age).
func (g *Guard) Accept(s *Signed, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.acceptLocked(s, now)
}

func (g *Guard) acceptLocked(s *Signed, now time.Time) error {
	if err := g.check(s, now); err != nil {
		return err
	}
	s = s.clone() // the caller keeps no handle on the held list
	if g.cur != nil {
		if s.Version < g.cur.Version {
			return ErrRollback
		}
		if s.Version == g.cur.Version {
			if !bytes.Equal(s.Encode(), g.cur.Encode()) {
				return ErrConflict
			}
			return nil
		}
	}
	if g.cur != nil && s.IssuedAt.Before(g.cur.IssuedAt) {
		return ErrOlder // a higher version must not also be an older statement
	}
	if g.store != nil {
		if err := g.store.Save(s); err != nil {
			return err
		}
	}
	g.adopt(s)
	return nil
}

// Refresh fetches the current list (from the gateway, which only relays it)
// and accepts it. On any failure the held list is kept, and keeps ageing.
func (g *Guard) Refresh(ctx context.Context, fetch func(context.Context) (*Signed, error), now time.Time) error {
	s, err := fetch(ctx)
	if err != nil {
		return err
	}
	return g.Accept(s, now)
}

// Status reports the held list's age. With no list, Stale is true.
func (g *Guard) Status(now time.Time) Status {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cur == nil {
		return Status{Stale: true}
	}
	age := max(now.Sub(g.cur.IssuedAt), 0)
	return Status{Version: g.cur.Version, Age: age, Warn: age > WarnAfter, Stale: age > RefuseAfter}
}

// CheckSend returns nil only if a fresh list is held and does not revoke
// deviceID. It returns ErrNoList, ErrStale or ErrRevoked otherwise.
func (g *Guard) CheckSend(deviceID string, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cur == nil {
		return ErrNoList
	}
	if now.Sub(g.cur.IssuedAt) > RefuseAfter {
		return ErrStale
	}
	if _, ok := g.set[deviceID]; ok {
		return ErrRevoked
	}
	return nil
}

// IsRevoked reports whether the held list revokes deviceID, ignoring age. It
// is for receive-side checks, where a stale list must still deny known-revoked
// devices.
func (g *Guard) IsRevoked(deviceID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.set[deviceID]
	return ok
}

// Renewer is the root holder's side: it re-signs the list on a schedule so
// everyone else's copy stays fresh.
type Renewer struct {
	Root   ed25519.PrivateKey
	Tenant string
	Guard  *Guard                               // the root holder's own copy
	Push   func(context.Context, *Signed) error // publish to the gateway
	mu     sync.Mutex                           // one renewal at a time, so pushes arrive in version order
}

// Renew signs the successor of the held list (adding any revocations), accepts
// it locally and publishes it. The local copy is updated first, so a failed
// publish still leaves the root holder's own sends correct; call again to retry.
func (r *Renewer) Renew(ctx context.Context, add []string, now time.Time) (*Signed, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Read, sign and adopt under one lock so concurrent renewals (the timer
	// and a manual revoke) get consecutive versions and none is lost.
	g := r.Guard
	g.mu.Lock()
	s, err := Next(r.Root, r.Tenant, g.cur, add, now)
	if err == nil {
		err = g.acceptLocked(s, now)
	}
	g.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.clone(), r.Push(ctx, s)
}

// Due reports whether the held list is old enough that the root holder's
// daemon should renew it.
func (g *Guard) Due(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cur == nil || now.Sub(g.cur.IssuedAt) >= RefreshEvery
}
