// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package revocation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

func signed(t *testing.T, priv ed25519.PrivateKey, ver uint64, at time.Time, ids ...string) *Signed {
	t.Helper()
	s, err := Sign(priv, List{Tenant: "t1", Version: ver, IssuedAt: at, Revoked: ids})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func guard(t *testing.T, pub ed25519.PublicKey, st Store) *Guard {
	t.Helper()
	g, err := NewGuard(pub, "t1", st, now)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestSignNormalisesAndVerifies(t *testing.T) {
	pub, priv := keys(t)
	s := signed(t, priv, 1, now.Add(time.Millisecond), "b", "a", "b")
	if !reflect.DeepEqual(s.Revoked, []string{"a", "b"}) {
		t.Fatal(s.Revoked)
	}
	if err := Verify(pub, s, now); err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, signed(t, priv, 1, now), now); err != nil { // empty list
		t.Fatal(err)
	}
}

func TestSignRejectsInvalid(t *testing.T) {
	_, priv := keys(t)
	for name, l := range map[string]List{
		"tenant":   {Version: 1, IssuedAt: now},
		"version":  {Tenant: "t", IssuedAt: now},
		"time":     {Tenant: "t", Version: 1},
		"empty id": {Tenant: "t", Version: 1, IssuedAt: now, Revoked: []string{""}},
	} {
		if _, err := Sign(priv, l); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, priv := keys(t)
	other, _ := keys(t)
	good := signed(t, priv, 1, now, "a")
	if err := Verify(other, good, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong root: %v", err)
	}
	if err := Verify(nil, good, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no root: %v", err)
	}
	if err := Verify(pub, nil, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil: %v", err)
	}
	for name, mut := range map[string]func(*Signed){
		"version": func(s *Signed) { s.Version++ },
		"time":    func(s *Signed) { s.IssuedAt = s.IssuedAt.Add(time.Hour) },
		"tenant":  func(s *Signed) { s.Tenant = "t2" },
		"drop":    func(s *Signed) { s.Revoked = nil },
		"add":     func(s *Signed) { s.Revoked = []string{"a", "b"} },
	} {
		c := *good
		mut(&c)
		if err := Verify(pub, &c, now.Add(2*time.Hour)); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := *good
	bad.Revoked = []string{"b", "a"}
	if err := Verify(pub, &bad, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsorted: %v", err)
	}
	if err := Verify(pub, signed(t, priv, 1, now.Add(MaxSkew+time.Minute)), now); !errors.Is(err, ErrFuture) {
		t.Fatalf("future: %v", err)
	}
	if err := Verify(pub, signed(t, priv, 1, now.Add(time.Minute)), now); err != nil {
		t.Fatal(err)
	}
}

func TestEncodeIsUnambiguous(t *testing.T) {
	a := List{Tenant: "t", Version: 1, IssuedAt: now, Revoked: []string{"ab", "c"}}
	b := List{Tenant: "t", Version: 1, IssuedAt: now, Revoked: []string{"a", "bc"}}
	if string(a.Encode()) == string(b.Encode()) {
		t.Fatal("field boundary ambiguous")
	}
}

func TestNext(t *testing.T) {
	_, priv := keys(t)
	first, err := Next(priv, "t1", nil, []string{"d2"}, now)
	if err != nil || first.Version != 1 || !reflect.DeepEqual(first.Revoked, []string{"d2"}) {
		t.Fatal(first, err)
	}
	later := now.Add(time.Hour)
	second, err := Next(priv, "t1", first, []string{"d1"}, later)
	if err != nil || second.Version != 2 || !second.IssuedAt.Equal(later) ||
		!reflect.DeepEqual(second.Revoked, []string{"d1", "d2"}) {
		t.Fatal(second, err)
	}
	refresh, err := Next(priv, "t1", second, nil, later)
	if err != nil || refresh.Version != 3 || len(refresh.Revoked) != 2 {
		t.Fatal(refresh, err)
	}
	if _, err := Next(priv, "t2", first, nil, now); !errors.Is(err, ErrTenant) {
		t.Fatal(err)
	}
	if _, err := Next(priv, "", nil, nil, now); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestGuardAccept(t *testing.T) {
	pub, priv := keys(t)
	g := guard(t, pub, nil)
	v2 := signed(t, priv, 2, now, "d1")
	if err := g.Accept(v2, now); err != nil {
		t.Fatal(err)
	}
	if err := g.Accept(v2, now); err != nil { // identical again
		t.Fatal(err)
	}
	if err := g.Accept(signed(t, priv, 1, now), now); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback to an emptier list: %v", err)
	}
	if err := g.Accept(signed(t, priv, 2, now, "d9"), now); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if !g.IsRevoked("d1") {
		t.Fatal("d1 should stay revoked")
	}
	_, evil := keys(t)
	if err := g.Accept(signed(t, evil, 9, now), now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged: %v", err)
	}
	other, _ := Sign(priv, List{Tenant: "t2", Version: 9, IssuedAt: now})
	if err := g.Accept(other, now); !errors.Is(err, ErrTenant) {
		t.Fatalf("tenant: %v", err)
	}
	if err := g.Accept(signed(t, priv, 3, now, "d1", "d2"), now); err != nil {
		t.Fatal(err)
	}
	if !g.IsRevoked("d2") || g.IsRevoked("d3") {
		t.Fatal("set not replaced")
	}
}

func TestCheckSendAndStatus(t *testing.T) {
	pub, priv := keys(t)
	g := guard(t, pub, nil)
	if err := g.CheckSend("d1", now); !errors.Is(err, ErrNoList) {
		t.Fatalf("no list: %v", err)
	}
	if st := g.Status(now); !st.Stale || st.Version != 0 {
		t.Fatal(st)
	}
	if !g.Due(now) {
		t.Fatal("no list is due")
	}
	if err := g.Accept(signed(t, priv, 1, now, "bad"), now); err != nil {
		t.Fatal(err)
	}
	if g.Due(now.Add(RefreshEvery-time.Second)) || !g.Due(now.Add(RefreshEvery)) {
		t.Fatal("due boundary")
	}
	cases := []struct {
		age         time.Duration
		warn, stale bool
	}{
		{0, false, false},
		{-time.Minute, false, false}, // clock behind: age clamps to zero
		{WarnAfter, false, false},
		{WarnAfter + time.Second, true, false},
		{RefuseAfter, true, false},
		{RefuseAfter + time.Second, true, true},
	}
	for _, c := range cases {
		st := g.Status(now.Add(c.age))
		if st.Warn != c.warn || st.Stale != c.stale || st.Version != 1 {
			t.Errorf("age %v: %+v", c.age, st)
		}
		err := g.CheckSend("good", now.Add(c.age))
		if c.stale != errors.Is(err, ErrStale) || (!c.stale && err != nil) {
			t.Errorf("age %v: send %v", c.age, err)
		}
	}
	if err := g.CheckSend("bad", now); !errors.Is(err, ErrRevoked) {
		t.Fatal(err)
	}
	if err := g.CheckSend("bad", now.Add(RefuseAfter+time.Hour)); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	if !g.IsRevoked("bad") || g.IsRevoked("good") {
		t.Fatal("IsRevoked")
	}
	if err := g.Accept(signed(t, priv, 2, now.Add(RefuseAfter), "bad"), now.Add(RefuseAfter)); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckSend("good", now.Add(RefuseAfter+time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestRefresh(t *testing.T) {
	pub, priv := keys(t)
	g := guard(t, pub, nil)
	ctx := context.Background()
	v1 := signed(t, priv, 1, now)
	if err := g.Refresh(ctx, func(context.Context) (*Signed, error) { return v1, nil }, now); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("gateway down")
	if err := g.Refresh(ctx, func(context.Context) (*Signed, error) { return nil, boom }, now); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	later := now.Add(RefuseAfter + time.Hour)
	if err := g.CheckSend("d", later); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	// A gateway replaying the old list does not freshen it.
	if err := g.Refresh(ctx, func(context.Context) (*Signed, error) { return v1, nil }, later); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckSend("d", later); !errors.Is(err, ErrStale) {
		t.Fatalf("replay must not freshen: %v", err)
	}
}

func TestRenewer(t *testing.T) {
	pub, priv := keys(t)
	g := guard(t, pub, nil)
	var pushed []*Signed
	r := &Renewer{Root: priv, Tenant: "t1", Guard: g, Push: func(_ context.Context, s *Signed) error {
		pushed = append(pushed, s)
		return nil
	}}
	ctx := context.Background()
	s, err := r.Renew(ctx, nil, now)
	if err != nil || s.Version != 1 || len(pushed) != 1 {
		t.Fatal(s, err)
	}
	s, err = r.Renew(ctx, []string{"d1"}, now.Add(WarnAfter))
	if err != nil || s.Version != 2 || !g.IsRevoked("d1") || len(pushed) != 2 {
		t.Fatal(s, err)
	}
	if st := g.Status(now.Add(WarnAfter)); st.Warn {
		t.Fatal("renewal should clear the warning")
	}
	r.Push = func(context.Context, *Signed) error { return errors.New("offline") }
	if _, err := r.Renew(ctx, []string{"d2"}, now.Add(WarnAfter)); err == nil || !g.IsRevoked("d2") {
		t.Fatal("expected push error with local update", err)
	}
	r.Tenant = "other"
	if _, err := r.Renew(ctx, nil, now); !errors.Is(err, ErrTenant) {
		t.Fatal(err)
	}
	_, evil := keys(t)
	r.Tenant, r.Root = "t1", evil
	if _, err := r.Renew(ctx, nil, now); !errors.Is(err, ErrBadSignature) {
		t.Fatal(err)
	}
}

func TestGuardPersistence(t *testing.T) {
	pub, priv := keys(t)
	path := filepath.Join(t.TempDir(), "revocations.json")
	g := guard(t, pub, NewFileStore(path))
	if err := g.Accept(signed(t, priv, 5, now, "d1"), now); err != nil {
		t.Fatal(err)
	}
	g2 := guard(t, pub, NewFileStore(path))
	if !g2.IsRevoked("d1") {
		t.Fatal("list lost across restart")
	}
	if err := g2.Accept(signed(t, priv, 4, now), now); !errors.Is(err, ErrRollback) {
		t.Fatal(err)
	}
	other, _ := keys(t)
	if _, err := NewGuard(other, "t1", NewFileStore(path), now); !errors.Is(err, ErrBadSignature) {
		t.Fatal(err)
	}
	if _, err := NewGuard(pub, "t2", NewFileStore(path), now); !errors.Is(err, ErrTenant) {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewGuard(pub, "t1", NewFileStore(path), now); !errors.Is(err, ErrStore) {
		t.Fatal(err)
	}
}

type failStore struct{ err error }

func (f failStore) Load() (*Signed, error) { return nil, nil }
func (f failStore) Save(*Signed) error     { return f.err }

func TestGuardFailsClosedWhenSaveFails(t *testing.T) {
	pub, priv := keys(t)
	g := guard(t, pub, failStore{ErrStore})
	if err := g.Accept(signed(t, priv, 1, now, "d1"), now); !errors.Is(err, ErrStore) {
		t.Fatal(err)
	}
	if g.IsRevoked("d1") || g.CheckSend("x", now) == nil {
		t.Fatal("unsaved list must not be adopted")
	}
}
