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

func TestSubSecondNotAfterDoesNotExtend(t *testing.T) {
	pub, priv := keys(t)
	b := sample(t, 1)
	b.NotAfter = now.Add(time.Hour)
	s, _ := Sign(priv, b)
	s.NotAfter = s.NotAfter.Add(900 * time.Millisecond) // not covered by the signature
	if err := Verify(pub, s, now.Add(time.Hour+500*time.Millisecond)); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

// lockedStore is a Locker whose Load starts failing after n successful calls.
type lockedStore struct{ loads, okLoads int }

func (s *lockedStore) Load() ([]Record, error) {
	s.loads++
	if s.loads > s.okLoads {
		return nil, ErrStore
	}
	return nil, nil
}
func (s *lockedStore) Save([]Record) error         { return nil }
func (s *lockedStore) Lock() (func() error, error) { return func() error { return nil }, nil }

// Another process may have corrupted the store since this one started: Accept
// re-reads it under the lock and must reject rather than judge from stale state.
func TestAcceptRejectsWhenStoreUnreadableUnderLock(t *testing.T) {
	rpub, rpriv := keys(t)
	tr, err := NewTracker(rpub, &lockedStore{okLoads: 1})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := Sign(rpriv, sample(t, 1))
	if err := tr.Accept(s, now); !errors.Is(err, ErrStore) {
		t.Fatalf("got %v", err)
	}
}

func TestTrackerVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tr, err := NewTracker(pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if v, ok := tr.Version("t", "d"); ok || v != 0 {
		t.Fatalf("an unseen device has version %d, %v", v, ok)
	}
	for _, ver := range []uint64{2, 5} {
		s, err := Sign(priv, Binding{Tenant: "t", Owner: "o", DeviceID: "d", SigningKey: pub, Version: ver, NotAfter: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.Accept(s, now); err != nil {
			t.Fatal(err)
		}
		if v, ok := tr.Version("t", "d"); !ok || v != ver {
			t.Fatalf("after version %d: %d, %v", ver, v, ok)
		}
	}
	for _, k := range [][2]string{{"t", "other"}, {"other", "d"}} {
		if _, ok := tr.Version(k[0], k[1]); ok {
			t.Fatalf("%v is reported as seen", k)
		}
	}
}

type memStore struct{ recs []Record }

func (m *memStore) Load() ([]Record, error) { return m.recs, nil }
func (m *memStore) Save(r []Record) error   { m.recs = r; return nil }

func TestTrackerOwner(t *testing.T) {
	rpub, rpriv := keys(t)
	tr, err := NewTracker(rpub, &memStore{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tr.Owner("t1", "d1"); ok {
		t.Fatal("an owner for a device nobody recorded")
	}
	s, err := Sign(rpriv, sample(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Accept(s, now); err != nil {
		t.Fatal(err)
	}
	if o, ok := tr.Owner("t1", "d1"); !ok || o != "a@x.io" {
		t.Fatalf("owner = %q, %v", o, ok)
	}
	if _, ok := tr.Owner("t2", "d1"); ok {
		t.Fatal("an owner across tenants")
	}
	if _, ok := tr.Owner("t1", "d2"); ok {
		t.Fatal("an owner for another device")
	}
}

func ownerOf(t *testing.T, root ed25519.PublicKey, enc []byte) (string, bool) {
	t.Helper()
	tr, err := NewTracker(root, &memStore{recs: []Record{{Tenant: "t1", DeviceID: "d1", Version: 1, Encoded: enc}}})
	if err != nil {
		t.Fatal(err)
	}
	return tr.Owner("t1", "d1")
}

// A record the tracker did not write itself (a damaged store file) gives no owner rather than a wrong one.
func TestTrackerOwnerDamagedRecords(t *testing.T) {
	rpub, _ := keys(t)
	good := Binding{Tenant: "t1", Owner: "a@x.io", DeviceID: "d1", SigningKey: make([]byte, 32), Version: 1, NotAfter: now}.Encode()
	field := func(p string) []byte { return append([]byte{0, 0, 0, byte(len(p))}, p...) }
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	cases := map[string][]byte{
		"empty":            nil,
		"short length":     good[:3],
		"label cut":        good[:10],
		"length too large": append([]byte{0x7f, 0xff, 0xff, 0xff}, "x"...),
		"wrong label":      cat(field("other"), field("t1"), field("a@x.io")),
		"wrong tenant":     cat(field(label), field("t9"), field("a@x.io")),
		"no owner":         cat(field(label), field("t1"), field("")),
		"owner missing":    cat(field(label), field("t1")),
		"owner cut":        cat(field(label), field("t1"), good[len(good)-1:]),
	}
	// The limits are exact: a length that is exactly what is left is fine (the owner may end the record), one more
	// byte than is left is not, and a length header with fewer than four bytes is not a header.
	exact := cat(field(label), field("t1"), field("a@x.io"))
	if o, ok := ownerOf(t, rpub, exact); !ok || o != "a@x.io" {
		t.Errorf("a record that ends with the owner: %q, %v", o, ok)
	}
	cases["owner one byte short"] = exact[:len(exact)-1]
	cases["header of three bytes"] = cat(field(label), field("t1")[:7])
	cases["header of four bytes, empty owner"] = cat(field(label), field("t1"), []byte{0, 0, 0, 0})
	for name, enc := range cases {
		tr, err := NewTracker(rpub, &memStore{recs: []Record{{Tenant: "t1", DeviceID: "d1", Version: 1, Encoded: enc}}})
		if err != nil {
			t.Fatal(err)
		}
		if o, ok := tr.Owner("t1", "d1"); ok {
			t.Errorf("%s: owner %q from a damaged record", name, o)
		}
	}
}
