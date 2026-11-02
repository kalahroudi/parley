// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package acceptance holds end-to-end checks that cross package boundaries.
// T107 (spike 2): the root, enrollment approval, binding versions, revocation
// and the recovery code, driven through the real code paths together.
package acceptance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/revocation"
	"github.com/kalahroudi/parley/internal/root"
)

var t0 = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

func deviceKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// approve is the admin daemon's side of enrollment: sign a binding for a device.
func approve(t *testing.T, rk ed25519.PrivateKey, id string, ver uint64, now time.Time) *binding.Signed {
	t.Helper()
	s, err := binding.Sign(rk, binding.Binding{Tenant: "acme", Owner: id + "@acme.test", DeviceID: id, SigningKey: deviceKey(t), Version: ver, NotAfter: now.Add(binding.Lifetime)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEnrollApproveRevoke(t *testing.T) {
	r, err := root.New()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	peer, err := binding.NewTracker(r.Public, binding.NewFileStore(filepath.Join(dir, "bindings.json")))
	if err != nil {
		t.Fatal(err)
	}
	lstore := revocation.NewFileStore(filepath.Join(dir, "revocations.json"))
	guard, err := revocation.NewGuard(r.Public, "acme", lstore, t0)
	if err != nil {
		t.Fatal(err)
	}
	// Before any list exists, sends fail closed.
	if err := guard.CheckSend("laptop", t0); !errors.Is(err, revocation.ErrNoList) {
		t.Fatalf("no list: %v", err)
	}
	renewer := &revocation.Renewer{Root: r.Private, Tenant: "acme", Guard: guard, Push: func(_ context.Context, _ *revocation.Signed) error { return nil }}
	if _, err := renewer.Renew(context.Background(), nil, t0); err != nil {
		t.Fatal(err)
	}

	// Enroll: the admin approves two devices; the peer accepts both bindings.
	laptop, phone := approve(t, r.Private, "laptop", 1, t0), approve(t, r.Private, "phone", 1, t0)
	for _, b := range []*binding.Signed{laptop, phone} {
		if err := peer.Accept(b, t0); err != nil {
			t.Fatal(err)
		}
		if err := guard.CheckSend(b.DeviceID, t0); err != nil {
			t.Fatalf("%s may be sent to: %v", b.DeviceID, err)
		}
	}

	// A binding signed by any other key, as a malicious gateway would forge, is refused.
	other, _ := root.New()
	if err := peer.Accept(approve(t, other.Private, "evil", 1, t0), t0); !errors.Is(err, binding.ErrBadSignature) {
		t.Fatalf("forged binding: %v", err)
	}

	// Revoke the phone: the signed list propagates and sends to it stop, the laptop is unaffected.
	later := t0.Add(time.Hour)
	list, err := renewer.Renew(context.Background(), []string{"phone"}, later)
	if err != nil {
		t.Fatal(err)
	}
	peerGuard, err := revocation.NewGuard(r.Public, "acme", nil, later)
	if err != nil {
		t.Fatal(err)
	}
	if err := peerGuard.Accept(list, later); err != nil {
		t.Fatal(err)
	}
	if err := peerGuard.CheckSend("phone", later); !errors.Is(err, revocation.ErrRevoked) {
		t.Fatalf("revoked phone: %v", err)
	}
	if err := peerGuard.CheckSend("laptop", later); err != nil {
		t.Fatalf("laptop: %v", err)
	}
	// A list not signed by the root is not accepted.
	forged, _ := revocation.Next(other.Private, "acme", nil, nil, later)
	if err := peerGuard.Accept(forged, later); !errors.Is(err, revocation.ErrBadSignature) {
		t.Fatalf("forged list: %v", err)
	}
}

func TestBindingRollbackRejectedAcrossRestart(t *testing.T) {
	r, _ := root.New()
	path := filepath.Join(t.TempDir(), "bindings.json")
	open := func() *binding.Tracker {
		tr, err := binding.NewTracker(r.Public, binding.NewFileStore(path))
		if err != nil {
			t.Fatal(err)
		}
		return tr
	}
	v1, v2 := approve(t, r.Private, "laptop", 1, t0), approve(t, r.Private, "laptop", 2, t0)
	tr := open()
	if err := tr.Accept(v1, t0); err != nil {
		t.Fatal(err)
	}
	if err := tr.Accept(v2, t0); err != nil {
		t.Fatal(err)
	}
	for name, tracker := range map[string]*binding.Tracker{"running": tr, "restarted": open()} {
		if err := tracker.Accept(v1, t0); !errors.Is(err, binding.ErrRollback) {
			t.Fatalf("%s daemon accepted old binding: %v", name, err)
		}
		if err := tracker.Accept(v2, t0); err != nil {
			t.Fatalf("%s daemon rejects current binding: %v", name, err)
		}
	}
	// Rotating the key means re-approval with a higher version.
	if err := open().Accept(approve(t, r.Private, "laptop", 3, t0), t0); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryCodeRestoresRoot(t *testing.T) {
	r, _ := root.New()
	// The admin loses the keychain entry; the backup file and written-down code remain.
	restored, err := root.Recover(r.RecoveryCode, r.Backup)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, r.Private) || root.Fingerprint(restored.Public().(ed25519.PublicKey)) != r.Fingerprint {
		t.Fatal("recovered a different root")
	}
	// Bindings and lists signed by the restored root verify against the pin from before the loss.
	if err := binding.Verify(r.Public, approve(t, restored, "laptop", 1, t0), t0); err != nil {
		t.Fatal(err)
	}
	l, err := revocation.Next(restored, "acme", nil, []string{"phone"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := revocation.Verify(r.Public, l, t0); err != nil {
		t.Fatal(err)
	}
	// A wrong code does not open it.
	wrong := strings.Repeat("A", len(strings.ReplaceAll(r.RecoveryCode, "-", "")))
	if _, err := root.Recover(wrong, r.Backup); !errors.Is(err, root.ErrBadRecovery) {
		t.Fatalf("wrong code: %v", err)
	}
	// The root key store round trip works too.
	st := root.FileStore{Dir: t.TempDir()}
	if err := st.Save(restored); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.Exists(); err != nil || !ok {
		t.Fatalf("restored root not stored: %v %v", ok, err)
	}
}

func TestStaleRevocationListBehavior(t *testing.T) {
	r, _ := root.New()
	path := filepath.Join(t.TempDir(), "revocations.json")
	store := revocation.NewFileStore(path)
	g, err := revocation.NewGuard(r.Public, "acme", store, t0)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := revocation.Next(r.Private, "acme", nil, []string{"phone"}, t0)
	if err := g.Accept(l, t0); err != nil {
		t.Fatal(err)
	}
	at := func(d time.Duration) time.Time { return t0.Add(d) }

	// Fresh: no warning, sends allowed. The daily refresh is due after a day.
	if s := g.Status(at(time.Hour)); s.Warn || s.Stale {
		t.Fatalf("fresh: %+v", s)
	}
	if g.Due(at(time.Hour)) || !g.Due(at(24*time.Hour)) {
		t.Fatal("refresh due after one day, not before")
	}
	// Past 7 days: warn but still send. Past 14 days: refuse to send.
	if s := g.Status(at(7*24*time.Hour + time.Minute)); !s.Warn || s.Stale {
		t.Fatalf("day 7: %+v", s)
	}
	if err := g.CheckSend("laptop", at(10*24*time.Hour)); err != nil {
		t.Fatalf("day 10 send: %v", err)
	}
	day15 := at(15 * 24 * time.Hour)
	if s := g.Status(day15); !s.Stale {
		t.Fatalf("day 15: %+v", s)
	}
	if err := g.CheckSend("laptop", day15); !errors.Is(err, revocation.ErrStale) {
		t.Fatalf("day 15 send: %v", err)
	}
	// Receive-side still denies a known-revoked device while stale.
	if !g.IsRevoked("phone") || g.IsRevoked("laptop") {
		t.Fatal("stale list must still deny revoked devices")
	}
	// A restart does not reset the clock: the persisted list is just as stale.
	g2, err := revocation.NewGuard(r.Public, "acme", store, day15)
	if err != nil {
		t.Fatal(err)
	}
	if err := g2.CheckSend("laptop", day15); !errors.Is(err, revocation.ErrStale) {
		t.Fatalf("after restart: %v", err)
	}
	// Refreshing from the gateway restores sending; an old list cannot be replayed to do so.
	fresh, _ := revocation.Next(r.Private, "acme", l, nil, day15)
	if err := g2.Accept(fresh, day15); err != nil {
		t.Fatal(err)
	}
	if err := g2.CheckSend("laptop", day15); err != nil {
		t.Fatalf("after refresh: %v", err)
	}
	if err := g2.CheckSend("phone", day15); !errors.Is(err, revocation.ErrRevoked) {
		t.Fatalf("phone stays revoked: %v", err)
	}
	if err := g2.Accept(l, day15); err == nil {
		t.Fatal("replaying the old list must fail")
	}
}
