// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package prekey

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

var fuzzNow = time.Unix(1_800_000_000, 0).UTC()

func fuzzPool(f *testing.F, signer ed25519.PrivateKey) *Pool {
	p, err := New(Config{Tenant: "t1", DeviceID: "dev-target", SigningKeyID: "k1", BindingVersion: 3,
		Signer: signer, AllowUnlocked: true, Capacity: 64, SweepEvery: time.Hour, Now: func() time.Time { return fuzzNow }})
	if err != nil {
		f.Fatal(err)
	}
	return p
}

// FuzzIssue throws arbitrary requests at the issuing side: caller, nonce and
// task expiry. Nothing may panic; an accepted request must be inside the
// documented limits and yield a prekey that verifies against the target's key
// and echoes the caller's nonce; and a refused request must not take a slot.
func FuzzIssue(f *testing.F) {
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	pub := signer.Public().(ed25519.PublicKey)
	p := fuzzPool(f, signer)
	f.Cleanup(func() { p.Close() })
	f.Add("dev-a", []byte{1, 2, 3}, int64(900))
	f.Add("", []byte{1}, int64(0))
	f.Add("dev-a", []byte{}, int64(0))
	f.Add("dev-a", make([]byte, MaxNonce+1), int64(0))
	f.Add(string(make([]byte, MaxCaller+1)), []byte{1}, int64(0))
	f.Add("dev-a", []byte{1}, int64(-5))
	f.Add("dev-a", []byte{1}, int64(1<<40))
	f.Fuzz(func(t *testing.T, caller string, nonce []byte, secs int64) {
		if p.Outstanding() > 48 { // free the slots; a real pool does this by expiry
			p.Close()
			p = fuzzPool(f, signer)
		}
		req := Request{Caller: caller, Nonce: nonce}
		if secs != 0 {
			req.TaskExpiry = fuzzNow.Add(time.Duration(secs%(1<<40)) * time.Second)
		}
		before := p.Outstanding()
		s, err := p.Issue(req)
		if err != nil {
			if p.Outstanding() != before {
				t.Fatalf("a refused request (%v) took a slot", err)
			}
			return
		}
		if caller == "" || len(caller) > MaxCaller || len(nonce) == 0 || len(nonce) > MaxNonce {
			t.Fatalf("an out-of-limits request was issued: caller %d bytes, nonce %d bytes", len(caller), len(nonce))
		}
		e := Expect{Tenant: "t1", DeviceID: "dev-target", SigningKeyID: "k1", Caller: caller, Nonce: nonce,
			BindingVersion: 3, Now: fuzzNow}
		if err := Verify(pub, s, e); err != nil {
			t.Fatalf("an issued prekey does not verify: %v", err)
		}
		if s.ExpiresAt.Sub(s.CreatedAt) > MaxTTL {
			t.Fatal("prekey outlives MaxTTL")
		}
	})
}

// FuzzVerify builds arbitrary signed prekeys (every field attacker-chosen, as a
// malicious gateway could hand them over) and verifies them against the
// caller's expectations. Nothing may panic, and nothing but the genuine prekey
// the target signed may verify.
func FuzzVerify(f *testing.F) {
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	pub := signer.Public().(ed25519.PublicKey)
	// Built by hand, not issued by a pool: the fuzzing workers are separate
	// processes, so the genuine prekey must be the same bytes in all of them.
	nonce := []byte("nonce-0123456789")
	pre := Prekey{Tenant: "t1", DeviceID: "dev-target", SigningKeyID: "k1", BindingVersion: 3,
		ID: [idSize]byte{1, 2, 3}, PublicKey: bytes.Repeat([]byte{9}, scalarSize), CallerDeviceID: "dev-a", Nonce: nonce,
		CreatedAt: fuzzNow, ExpiresAt: fuzzNow.Add(DefaultTTL)}
	g := &Signed{Prekey: pre, Signature: ed25519.Sign(signer, pre.Encode())}
	e := Expect{Tenant: "t1", DeviceID: "dev-target", SigningKeyID: "k1", Caller: "dev-a", Nonce: nonce, BindingVersion: 3, Now: fuzzNow}
	add := func(s Signed) {
		f.Add(s.Tenant, s.DeviceID, s.SigningKeyID, s.BindingVersion, s.ID[:], s.PublicKey, s.CallerDeviceID, s.Nonce,
			s.CreatedAt.Unix(), s.ExpiresAt.Unix(), s.Signature)
	}
	add(*g)
	bad := *g
	bad.BindingVersion++
	add(bad)
	bad = *g
	bad.PublicKey = bad.PublicKey[:31]
	add(bad)
	add(Signed{})
	f.Fuzz(func(t *testing.T, tenant, device, keyID string, bver uint64, id, pk []byte, caller string, n []byte, created, expires int64, sig []byte) {
		s := Signed{Prekey: Prekey{Tenant: tenant, DeviceID: device, SigningKeyID: keyID, BindingVersion: bver,
			PublicKey: pk, CallerDeviceID: caller, Nonce: n, CreatedAt: time.Unix(created, 0), ExpiresAt: time.Unix(expires, 0)},
			Signature: sig}
		copy(s.ID[:], id)
		if Verify(pub, &s, e) == nil && !bytes.Equal(s.Encode(), g.Encode()) {
			t.Fatalf("a prekey the target never signed verified: %+v", s)
		}
		_ = Verify(nil, &s, e)
		_ = Verify(pub, nil, e)
	})
}
