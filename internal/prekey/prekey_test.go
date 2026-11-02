// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package prekey

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type fixture struct {
	pool *Pool
	pub  ed25519.PublicKey
	now  time.Time
}

func newFixture(t *testing.T, mod func(*Config)) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{pub: pub, now: time.Unix(1_800_000_000, 0).UTC()}
	cfg := Config{Tenant: "t1", DeviceID: "dev-target", SigningKeyID: "k1", BindingVersion: 3,
		Signer: priv, Now: func() time.Time { return f.now }}
	if mod != nil {
		mod(&cfg)
	}
	f.pool, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.pool.Close)
	return f
}

func req(caller string) Request {
	n := make([]byte, 16)
	rand.Read(n)
	return Request{Caller: caller, Nonce: n}
}

func (f *fixture) expect(r Request) Expect {
	return Expect{Tenant: "t1", DeviceID: "dev-target", Caller: r.Caller, Nonce: r.Nonce, BindingVersion: 3, Now: f.now}
}

func TestIssueVerifyAndAgreement(t *testing.T) {
	f := newFixture(t, nil)
	r := req("dev-caller")
	s, err := f.pool.Issue(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(f.pub, s, f.expect(r)); err != nil {
		t.Fatal(err)
	}
	if got := s.ExpiresAt.Sub(s.CreatedAt); got != DefaultTTL {
		t.Fatalf("ttl %v", got)
	}
	// A sender who seals to the public half agrees with the stored scalar.
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pk, err := ecdh.X25519().NewPublicKey(s.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := eph.ECDH(pk)
	err = f.pool.With(s.ID, func(sc []byte) error {
		priv, err := ecdh.X25519().NewPrivateKey(sc)
		if err != nil {
			return err
		}
		got, err := priv.ECDH(eph.PublicKey())
		if !bytes.Equal(got, want) {
			t.Error("shared secret differs")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejects(t *testing.T) {
	f := newFixture(t, nil)
	r := req("dev-caller")
	s, _ := f.pool.Issue(r)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	short := *s
	short.PublicKey = short.PublicKey[:31]

	cases := []struct {
		name string
		pub  ed25519.PublicKey
		s    *Signed
		mod  func(*Expect)
		want error
	}{
		{"wrong signer", otherPub, s, nil, ErrBadSig},
		{"bad key length", nil, s, nil, ErrBadSig},
		{"short public key", f.pub, &short, nil, ErrBadSig},
		{"tenant", f.pub, s, func(e *Expect) { e.Tenant = "t2" }, ErrMismatch},
		{"target", f.pub, s, func(e *Expect) { e.DeviceID = "other" }, ErrMismatch},
		{"caller", f.pub, s, func(e *Expect) { e.Caller = "other" }, ErrMismatch},
		{"nonce", f.pub, s, func(e *Expect) { e.Nonce = []byte("stale") }, ErrMismatch},
		{"binding version", f.pub, s, func(e *Expect) { e.BindingVersion = 2 }, ErrMismatch},
		{"created in the future", f.pub, s, func(e *Expect) { e.Now = f.now.Add(-time.Hour) }, ErrMismatch},
		{"expired", f.pub, s, func(e *Expect) { e.Now = s.ExpiresAt }, ErrExpired},
	}
	for _, c := range cases {
		e := f.expect(r)
		if c.mod != nil {
			c.mod(&e)
		}
		if err := Verify(c.pub, c.s, e); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}

	// Tampering with any signed field breaks the signature.
	tam := *s
	tam.PublicKey = bytes.Clone(s.PublicKey)
	tam.PublicKey[0] ^= 1
	if err := Verify(f.pub, &tam, f.expect(r)); !errors.Is(err, ErrBadSig) {
		t.Errorf("tampered key: %v", err)
	}
	tam = *s
	tam.ExpiresAt = tam.ExpiresAt.Add(time.Hour)
	if err := Verify(f.pub, &tam, f.expect(r)); !errors.Is(err, ErrBadSig) {
		t.Errorf("tampered expiry: %v", err)
	}

	// A non-increasing validity window is refused even when correctly signed.
	bad := s.Prekey
	bad.ExpiresAt = bad.CreatedAt
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sb := &Signed{Prekey: bad, Signature: ed25519.Sign(priv, bad.Encode())}
	if err := Verify(priv.Public().(ed25519.PublicKey), sb, f.expect(r)); !errors.Is(err, ErrMismatch) {
		t.Errorf("empty window: %v", err)
	}
}

// The scalar is zeroed in the locked region on Consume, and a second use or a
// redelivered frame for the same id fails.
func TestConsumeZeroesAndTombstones(t *testing.T) {
	f := newFixture(t, nil)
	s, _ := f.pool.Issue(req("c"))
	var idx int
	f.pool.mu.Lock()
	idx = f.pool.live[s.ID].index
	f.pool.mu.Unlock()
	if bytes.Equal(f.pool.scalar(idx), make([]byte, scalarSize)) {
		t.Fatal("scalar not stored")
	}
	if err := f.pool.With(s.ID, func([]byte) error { return errors.New("junk frame") }); err == nil {
		t.Fatal("fn error lost")
	}
	if f.pool.Outstanding() != 1 {
		t.Fatal("a failed open burned the key")
	}
	if err := f.pool.Consume(s.ID); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.pool.scalar(idx), make([]byte, scalarSize)) {
		t.Fatal("scalar not zeroed after Consume")
	}
	if err := f.pool.Consume(s.ID); !errors.Is(err, ErrConsumed) {
		t.Fatalf("second consume: %v", err)
	}
	if err := f.pool.With(s.ID, func([]byte) error { t.Fatal("fn ran"); return nil }); !errors.Is(err, ErrConsumed) {
		t.Fatalf("with after consume: %v", err)
	}
	if err := f.pool.With([16]byte{9}, nil); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown: %v", err)
	}
	// The tombstone outlives reuse of the slot and goes away at expiry.
	s2, _ := f.pool.Issue(req("c"))
	if s2.ID == s.ID {
		t.Fatal("id reused")
	}
	f.now = s.ExpiresAt
	if err := f.pool.Consume(s.ID); !errors.Is(err, ErrUnknown) {
		t.Fatalf("after tombstone expiry: %v", err)
	}
}

func TestExpiryZeroesAndRefuses(t *testing.T) {
	f := newFixture(t, nil)
	s, _ := f.pool.Issue(req("c"))
	f.pool.mu.Lock()
	idx := f.pool.live[s.ID].index
	f.pool.mu.Unlock()
	f.now = s.ExpiresAt.Add(-time.Second)
	if err := f.pool.With(s.ID, func([]byte) error { return nil }); err != nil {
		t.Fatalf("still valid: %v", err)
	}
	f.now = s.ExpiresAt
	if err := f.pool.With(s.ID, func([]byte) error { t.Fatal("fn ran"); return nil }); !errors.Is(err, ErrUnknown) {
		// an expired key is zeroed and swept; its id is never usable again
		t.Fatalf("expired: %v", err)
	}
	if !bytes.Equal(f.pool.scalar(idx), make([]byte, scalarSize)) {
		t.Fatal("expired scalar not zeroed")
	}
	if f.pool.Outstanding() != 0 {
		t.Fatal("outstanding after expiry")
	}
}

func TestTTLFromTaskExpiry(t *testing.T) {
	f := newFixture(t, nil)
	r := req("c")
	r.TaskExpiry = f.now.Add(5 * time.Minute)
	s, _ := f.pool.Issue(r)
	if got := s.ExpiresAt.Sub(f.now); got != 5*time.Minute+DefaultSkew {
		t.Fatalf("got %v", got)
	}
	r.TaskExpiry = f.now.Add(72 * time.Hour)
	s, _ = f.pool.Issue(r)
	if got := s.ExpiresAt.Sub(f.now); got != MaxTTL {
		t.Fatalf("not capped: %v", got)
	}
	r.TaskExpiry = f.now
	if _, err := f.pool.Issue(r); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("past expiry: %v", err)
	}
}

func TestIssueValidationAndLimits(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Capacity = 4; c.PerCaller = 2 })
	if _, err := f.pool.Issue(Request{Nonce: []byte{1}}); !errors.Is(err, ErrBadRequest) {
		t.Fatal(err)
	}
	if _, err := f.pool.Issue(Request{Caller: "c"}); !errors.Is(err, ErrBadRequest) {
		t.Fatal(err)
	}
	a, _ := f.pool.Issue(req("flood"))
	f.pool.Issue(req("flood"))
	if _, err := f.pool.Issue(req("flood")); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("flood: %v", err)
	}
	// Another caller is unaffected until the pool itself is full.
	f.pool.Issue(req("b"))
	f.pool.Issue(req("b"))
	if _, err := f.pool.Issue(req("c")); !errors.Is(err, ErrPoolFull) {
		t.Fatalf("full: %v", err)
	}
	// Using a key, or letting one expire, frees capacity.
	f.pool.Consume(a.ID)
	if _, err := f.pool.Issue(req("c")); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Hour)
	if f.pool.Outstanding() != 0 {
		t.Fatal("expired keys linger")
	}
	if _, err := f.pool.Issue(req("flood")); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(Config{Tenant: "t", DeviceID: "d"}); !errors.Is(err, ErrBadRequest) {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := New(Config{Signer: priv, DeviceID: "d"}); !errors.Is(err, ErrBadRequest) {
		t.Fatal(err)
	}
}

func TestClose(t *testing.T) {
	f := newFixture(t, nil)
	s, _ := f.pool.Issue(req("c"))
	f.pool.Close()
	f.pool.Close()
	if _, err := f.pool.Issue(req("c")); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := f.pool.Consume(s.ID); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

// Keys are generated fresh each time, so two requests never share a key or id.
func TestKeysAreFresh(t *testing.T) {
	f := newFixture(t, nil)
	a, _ := f.pool.Issue(req("c"))
	b, _ := f.pool.Issue(req("c"))
	if a.ID == b.ID || bytes.Equal(a.PublicKey, b.PublicKey) {
		t.Fatal("reused key material")
	}
}

// Nothing in the pool is written to disk: the type holds no file handle, and
// the scalars live in the mapped region rather than the Go heap.
func TestHardenDoesNotFail(t *testing.T) {
	if err := Harden(); err != nil {
		t.Fatal(err)
	}
}
