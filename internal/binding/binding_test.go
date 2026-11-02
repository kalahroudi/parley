// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

var now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sample(t *testing.T, ver uint64) Binding {
	dev, _ := keys(t)
	return Binding{Tenant: "t1", Owner: "a@x.io", DeviceID: "d1", SigningKey: dev, Version: ver, NotAfter: now.Add(Lifetime)}
}

func TestSignVerify(t *testing.T) {
	rpub, rpriv := keys(t)
	s, err := Sign(rpriv, sample(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(rpub, s, now); err != nil {
		t.Fatal(err)
	}
	if err := Verify(rpub, s, s.NotAfter.Add(-time.Second)); err != nil {
		t.Fatal("valid until not_after:", err)
	}
	for _, at := range []time.Time{s.NotAfter, s.NotAfter.Add(time.Hour)} {
		if err := Verify(rpub, s, at); !errors.Is(err, ErrExpired) {
			t.Fatalf("at %v: %v", at, err)
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	rpub, rpriv := keys(t)
	otherPub, _ := keys(t)
	good, _ := Sign(rpriv, sample(t, 1))
	if err := Verify(otherPub, good, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong root: %v", err)
	}
	if err := Verify(nil, good, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no root: %v", err)
	}
	if err := Verify(rpub, nil, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil: %v", err)
	}
	mut := map[string]func(s *Signed){
		"tenant":  func(s *Signed) { s.Tenant = "t2" },
		"owner":   func(s *Signed) { s.Owner = "evil@x.io" },
		"device":  func(s *Signed) { s.DeviceID = "d2" },
		"key":     func(s *Signed) { s.SigningKey, _ = keys(t) },
		"version": func(s *Signed) { s.Version++ },
		"expiry":  func(s *Signed) { s.NotAfter = s.NotAfter.Add(time.Hour) },
		"sig":     func(s *Signed) { s.Signature = append([]byte{}, s.Signature...); s.Signature[0] ^= 1 },
	}
	for name, f := range mut {
		c := *good
		f(&c)
		if err := Verify(rpub, &c, now); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestInvalidFields(t *testing.T) {
	_, rpriv := keys(t)
	for name, f := range map[string]func(b *Binding){
		"tenant":  func(b *Binding) { b.Tenant = "" },
		"owner":   func(b *Binding) { b.Owner = "" },
		"device":  func(b *Binding) { b.DeviceID = "" },
		"version": func(b *Binding) { b.Version = 0 },
		"key":     func(b *Binding) { b.SigningKey = b.SigningKey[:5] },
		"expiry":  func(b *Binding) { b.NotAfter = time.Time{} },
	} {
		b := sample(t, 1)
		f(&b)
		if _, err := Sign(rpriv, b); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A hand-built Signed with an invalid field fails verify too.
	rpub, _ := keys(t)
	if err := Verify(rpub, &Signed{}, now); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestEncodingUnambiguous(t *testing.T) {
	a := sample(t, 1)
	b := a
	a.Tenant, a.Owner = "ab", "c"
	b.Tenant, b.Owner = "a", "bc"
	if string(a.Encode()) == string(b.Encode()) {
		t.Fatal("field boundary ambiguity")
	}
	c := a
	if string(a.Encode()) != string(c.Encode()) {
		t.Fatal("not deterministic")
	}
}

func TestTrackerRollback(t *testing.T) {
	rpub, rpriv := keys(t)
	tr, _ := NewTracker(rpub, nil)
	v2, _ := Sign(rpriv, sample(t, 2))
	v1 := *v2
	v1.Version = 1
	v1s, _ := Sign(rpriv, v1.Binding)
	v3b := v2.Binding
	v3b.Version = 3
	v3, _ := Sign(rpriv, v3b)

	if err := tr.Accept(v2, now); err != nil {
		t.Fatal(err)
	}
	if err := tr.Accept(v2, now); err != nil {
		t.Fatal("same version again:", err)
	}
	if err := tr.Accept(v1s, now); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback: %v", err)
	}
	if err := tr.Accept(v3, now); err != nil {
		t.Fatal(err)
	}
	if err := tr.Accept(v2, now); !errors.Is(err, ErrRollback) {
		t.Fatalf("after v3: %v", err)
	}
	// Other devices are tracked independently.
	ob := v1.Binding
	ob.DeviceID = "d9"
	other, _ := Sign(rpriv, ob)
	if err := tr.Accept(other, now); err != nil {
		t.Fatal(err)
	}
	// A rejected binding must not advance the version.
	bad := *v3
	bad.Version = 99
	if err := tr.Accept(&bad, now); !errors.Is(err, ErrBadSignature) {
		t.Fatal(err)
	}
	if err := tr.Accept(v3, now); err != nil {
		t.Fatal("version advanced by rejected binding:", err)
	}
}

func TestTrackerSameVersionDifferentBinding(t *testing.T) {
	rpub, rpriv := keys(t)
	tr, _ := NewTracker(rpub, nil)
	a, _ := Sign(rpriv, sample(t, 1))
	b, _ := Sign(rpriv, sample(t, 1)) // same device, different signing key
	if err := tr.Accept(a, now); err != nil {
		t.Fatal(err)
	}
	if err := tr.Accept(b, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("got %v", err)
	}
}

func TestTrackerKeyNoCollision(t *testing.T) {
	rpub, rpriv := keys(t)
	tr, _ := NewTracker(rpub, nil)
	x := sample(t, 5)
	x.Tenant, x.DeviceID = "a\x00b", "c"
	y := sample(t, 1)
	y.Tenant, y.DeviceID = "a", "b\x00c"
	sx, _ := Sign(rpriv, x)
	sy, _ := Sign(rpriv, y)
	if err := tr.Accept(sx, now); err != nil {
		t.Fatal(err)
	}
	if err := tr.Accept(sy, now); err != nil {
		t.Fatal("distinct device treated as rollback:", err)
	}
}
