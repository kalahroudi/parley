// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/revocation"
	"github.com/kalahroudi/parley/internal/root"
)

var t0 = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

var tenantSeq atomic.Int64

// gatewayFor returns a gateway base URL and tenant id: the real Worker when
// PARLEY_TEST_GATEWAY_HTTP is set (with DEV_AUTH on, as `wrangler dev --var
// DEV_AUTH:1` does), an in-process fake otherwise.
func gatewayFor(t *testing.T) (url, tenant string) {
	tenant = fmt.Sprintf("acc%d-%d", os.Getpid(), tenantSeq.Add(1))
	if u := os.Getenv("PARLEY_TEST_GATEWAY_HTTP"); u != "" {
		return u, tenant
	}
	return newFake(t, tenant), tenant
}

func newKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// node is one machine: a daemon with persisted binding and revocation state.
type node struct {
	t      *testing.T
	dir    string
	pin    ed25519.PublicKey
	tenant string
	client *Client
	d      *Daemon
}

// boot (re)starts the daemon from its files, as a restart does.
func (n *node) boot() {
	n.t.Helper()
	tr, err := binding.NewTracker(n.pin, binding.NewFileStore(filepath.Join(n.dir, "bindings.json")))
	if err != nil {
		n.t.Fatal(err)
	}
	g, err := revocation.NewGuard(n.pin, n.tenant, revocation.NewFileStore(filepath.Join(n.dir, "revocations.json")), t0)
	if err != nil {
		n.t.Fatal(err)
	}
	n.d = &Daemon{Tracker: tr, Guard: g, Client: n.client, Tenant: n.tenant}
}

func newNode(t *testing.T, pin ed25519.PublicKey, url, tenant, email string) *node {
	n := &node{t: t, dir: t.TempDir(), pin: pin, tenant: tenant, client: &Client{BaseURL: url, Auth: "Bearer dev-user:" + tenant + ":" + email}}
	n.boot()
	return n
}

// enroll runs the device side in the background and returns where its result lands.
type enrolled struct {
	b   *binding.Signed
	err error
}

func (n *node) enroll(ctx context.Context, name string, key ed25519.PublicKey, clock func() time.Time) <-chan enrolled {
	ch := make(chan enrolled, 1)
	go func() {
		b, err := n.d.Enroll(ctx, name, key, 20*time.Millisecond, clock)
		ch <- enrolled{b, err}
	}()
	return ch
}

func pendingFor(t *testing.T, a *Admin, owner string) Pending {
	t.Helper()
	for i := 0; i < 500; i++ {
		ps, err := a.Client.Pending(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range ps {
			if p.Owner == owner {
				return p
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no pending request from %s", owner)
	return Pending{}
}

func wait(t *testing.T, ch <-chan enrolled) enrolled {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(20 * time.Second):
		t.Fatal("enrollment did not finish")
		return enrolled{}
	}
}

// adminNode is the root holder's machine: the root, its own copy of the list, the Admin.
func adminNode(t *testing.T, r *root.Root, url, tenant string) (*Admin, *revocation.Guard, string) {
	dir := t.TempDir()
	g, err := revocation.NewGuard(r.Public, tenant, revocation.NewFileStore(filepath.Join(dir, "revocations.json")), t0)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{BaseURL: url, Auth: "Bearer dev-admin:" + tenant}
	return NewAdmin(r.Private, tenant, c, g), g, dir
}

func TestEndToEnd(t *testing.T) {
	url, tenant := gatewayFor(t)
	ctx := context.Background()
	now := t0
	clock := func() time.Time { return now }

	r, err := root.New()
	if err != nil {
		t.Fatal(err)
	}
	admin, _, adminDir := adminNode(t, r, url, tenant)
	if ok, err := admin.RenewIfDue(ctx, now); err != nil || !ok {
		t.Fatalf("first list: %v %v", ok, err)
	}
	if ok, err := admin.RenewIfDue(ctx, now.Add(time.Hour)); err != nil || ok {
		t.Fatalf("renewed before due: %v %v", ok, err)
	}

	// Enroll and approve: alice, bob and erin are approved; dave is rejected; carol's
	// device pins a different root (a gateway-substituted fingerprint) and refuses the binding.
	alice, bob, erin := newNode(t, r.Public, url, tenant, "alice@acme.test"), newNode(t, r.Public, url, tenant, "bob@acme.test"), newNode(t, r.Public, url, tenant, "erin@acme.test")
	other, _ := root.New()
	carol, dave := newNode(t, other.Public, url, tenant, "carol@acme.test"), newNode(t, r.Public, url, tenant, "dave@acme.test")
	keys := map[string]ed25519.PublicKey{}
	results := map[string]<-chan enrolled{}
	for name, n := range map[string]*node{"alice": alice, "bob": bob, "erin": erin, "carol": carol, "dave": dave} {
		keys[name] = newKey(t)
		results[name] = n.enroll(ctx, name+"-laptop", keys[name], clock)
	}
	for _, name := range []string{"alice", "bob", "erin", "carol"} {
		if err := admin.Approve(ctx, pendingFor(t, admin, name+"@acme.test"), 1, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := admin.Reject(ctx, pendingFor(t, admin, "dave@acme.test")); err != nil {
		t.Fatal(err)
	}
	bind := map[string]*binding.Signed{}
	for _, name := range []string{"alice", "bob", "erin"} {
		e := wait(t, results[name])
		if e.err != nil {
			t.Fatalf("%s: %v", name, e.err)
		}
		bind[name] = e.b
		if e.b.Owner != name+"@acme.test" || e.b.Tenant != tenant || e.b.Version != 1 || !e.b.SigningKey.Equal(keys[name]) {
			t.Fatalf("%s binding: %+v", name, e.b.Binding)
		}
	}
	if e := wait(t, results["carol"]); !errors.Is(e.err, binding.ErrBadSignature) {
		t.Fatalf("a binding not signed by the pinned root must be refused: %v", e.err)
	}
	if e := wait(t, results["dave"]); !errors.Is(e.err, ErrRejected) {
		t.Fatalf("rejected: %v", e.err)
	}

	// Alice has no list until she fetches one: sends fail closed. Then she can send to bob.
	if err := alice.d.AuthorizeSend(bind["bob"], now); !errors.Is(err, revocation.ErrNoList) {
		t.Fatalf("no list: %v", err)
	}
	if w := alice.d.Warning(now); !strings.Contains(w, "no revocation list") {
		t.Fatalf("warning: %q", w)
	}
	if err := alice.d.Refresh(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := alice.d.AuthorizeSend(bind["bob"], now); err != nil || alice.d.Warning(now) != "" {
		t.Fatalf("alice to bob: %v %q", err, alice.d.Warning(now))
	}

	// Revoke bob. Until alice's daemon refreshes she still sends (propagation is at most one
	// refresh interval); after it, sends to bob are refused and erin is unaffected.
	now = now.Add(time.Hour)
	if _, err := admin.Revoke(ctx, []string{bind["bob"].DeviceID}, now); err != nil {
		t.Fatal(err)
	}
	if err := alice.d.AuthorizeSend(bind["bob"], now); err != nil {
		t.Fatalf("before refresh: %v", err)
	}
	if err := alice.d.Refresh(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := alice.d.AuthorizeSend(bind["bob"], now); !errors.Is(err, revocation.ErrRevoked) {
		t.Fatalf("after refresh: %v", err)
	}
	if err := alice.d.AuthorizeSend(bind["erin"], now); err != nil {
		t.Fatalf("erin: %v", err)
	}

	// Binding rollback: erin is re-approved at version 2; the old binding is rejected, and still
	// is after alice's daemon restarts from its persisted store. The gateway refuses it too.
	if err := admin.Approve(ctx, Pending{ID: bind["erin"].DeviceID, Owner: "erin@acme.test", SigningKey: keys["erin"]}, 2, now); err != nil {
		t.Fatal(err)
	}
	if _, err := erin.client.EnrollmentStatus(ctx, tenant, bind["erin"].DeviceID, "wrong"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("status needs the poll secret: %v", err)
	}
	erin2 := *bind["erin"]
	erin2.Version = 2
	signed2, err := binding.Sign(r.Private, erin2.Binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.d.AuthorizeSend(signed2, now); err != nil {
		t.Fatal(err)
	}
	if err := admin.Approve(ctx, Pending{ID: bind["erin"].DeviceID, Owner: "erin@acme.test", SigningKey: keys["erin"]}, 1, now); err == nil {
		t.Fatal("the gateway must refuse a lower binding version")
	}
	if err := alice.d.AuthorizeSend(bind["erin"], now); !errors.Is(err, binding.ErrRollback) {
		t.Fatalf("old binding: %v", err)
	}
	alice.boot()
	if err := alice.d.AuthorizeSend(bind["erin"], now); !errors.Is(err, binding.ErrRollback) {
		t.Fatalf("old binding after restart: %v", err)
	}
	if err := alice.d.AuthorizeSend(signed2, now); err != nil {
		t.Fatalf("current binding after restart: %v", err)
	}
	if err := alice.d.AuthorizeSend(bind["bob"], now); !errors.Is(err, revocation.ErrRevoked) {
		t.Fatalf("revocation survives restart: %v", err)
	}

	// Recovery: the admin loses the key store and restores the root from the backup and
	// recovery code. The restored root signs a valid next binding and list, accepted by
	// daemons that only pinned the original public key.
	key, err := root.Recover(r.RecoveryCode, r.Backup)
	if err != nil {
		t.Fatal(err)
	}
	restored := &root.Root{Private: key, Public: key.Public().(ed25519.PublicKey)}
	if restored.Public.Equal(r.Public) == false {
		t.Fatal("recovered a different root")
	}
	g2, err := revocation.NewGuard(restored.Public, tenant, revocation.NewFileStore(filepath.Join(adminDir, "revocations.json")), now)
	if err != nil {
		t.Fatal(err)
	}
	admin2 := NewAdmin(restored.Private, tenant, admin.Client, g2)
	frank := newNode(t, r.Public, url, tenant, "frank@acme.test")
	frankKey := newKey(t)
	done := frank.enroll(ctx, "frank-laptop", frankKey, clock)
	if err := admin2.Approve(ctx, pendingFor(t, admin2, "frank@acme.test"), 1, now); err != nil {
		t.Fatal(err)
	}
	if e := wait(t, done); e.err != nil {
		t.Fatalf("binding from the restored root: %v", e.err)
	}
	now = now.Add(time.Hour)
	if _, err := admin2.Revoke(ctx, []string{"gone"}, now); err != nil {
		t.Fatal(err)
	}
	if err := alice.d.Refresh(ctx, now); err != nil {
		t.Fatalf("list from the restored root: %v", err)
	}
	if !alice.d.Guard.IsRevoked("gone") || !alice.d.Guard.IsRevoked(bind["bob"].DeviceID) {
		t.Fatal("restored root's list must carry the earlier revocations")
	}

	// Stale list: the gateway becomes unreachable. Alice's list keeps ageing from its issue
	// time; she warns after 7 days and refuses to send after 14, but still denies revoked devices.
	issued := now
	alice.client = &Client{BaseURL: "http://127.0.0.1:1", Auth: alice.client.Auth}
	alice.d.Client = alice.client
	if err := alice.d.Refresh(ctx, issued.Add(8*day)); err == nil {
		t.Fatal("refresh against a dead gateway must fail")
	}
	if w := alice.d.Warning(issued.Add(8 * day)); !strings.Contains(w, "8 days") || !strings.Contains(w, "14") {
		t.Fatalf("warning at 8 days: %q", w)
	}
	if err := alice.d.AuthorizeSend(signed2, issued.Add(8*day)); err != nil {
		t.Fatalf("warned, not refused: %v", err)
	}
	if err := alice.d.AuthorizeSend(signed2, issued.Add(15*day)); !errors.Is(err, revocation.ErrStale) {
		t.Fatalf("15 days: %v", err)
	}
	if w := alice.d.Warning(issued.Add(15 * day)); !strings.Contains(w, "15 days") || !strings.Contains(w, "refused until") {
		t.Fatalf("warning at 15 days: %q", w)
	}
	if !alice.d.Guard.IsRevoked(bind["bob"].DeviceID) {
		t.Fatal("a stale list still denies revoked devices")
	}
	// The admin's daemon renews (a day or more after the last list), the gateway serves it, sends resume.
	now = issued.Add(15 * day)
	if ok, err := admin2.RenewIfDue(ctx, now); err != nil || !ok {
		t.Fatalf("renew: %v %v", ok, err)
	}
	alice.client = &Client{BaseURL: url, Auth: alice.client.Auth}
	alice.d.Client = alice.client
	if err := alice.d.Refresh(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := alice.d.AuthorizeSend(signed2, now); err != nil || alice.d.Warning(now) != "" {
		t.Fatalf("after refresh: %v %q", err, alice.d.Warning(now))
	}
}

// A root clock that goes back by more than the skew cannot renew: Renew fails with
// ErrFuture, nothing is published, the held list stays, and it keeps ageing toward
// the 7-day warning and the 14-day refusal.
func TestRootClockWentBackwards(t *testing.T) {
	url, tenant := gatewayFor(t)
	ctx := context.Background()
	r, _ := root.New()
	admin, adminGuard, _ := adminNode(t, r, url, tenant)
	if _, err := admin.Revoke(ctx, []string{"old"}, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Revoke(ctx, []string{"bob"}, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	issued := t0.Add(time.Hour)
	peer := newNode(t, r.Public, url, tenant, "p@acme.test")
	if err := peer.d.Refresh(ctx, issued); err != nil {
		t.Fatal(err)
	}

	back := issued.Add(-revocation.MaxSkew - time.Minute)
	if _, err := admin.Revoke(ctx, []string{"never"}, back); !errors.Is(err, revocation.ErrFuture) {
		t.Fatalf("renew with the clock back: %v", err)
	}
	if ok, err := admin.RenewIfDue(ctx, back); ok || err != nil {
		t.Fatalf("not due at an earlier time: %v %v", ok, err)
	}
	for _, g := range []*revocation.Guard{adminGuard, peer.d.Guard} {
		if g.IsRevoked("never") || !g.IsRevoked("bob") || g.Status(issued).Version != 2 {
			t.Fatal("the held list must not change")
		}
	}
	got, err := admin.Client.FetchRevocations(ctx, tenant)
	if err != nil || got.Version != 2 || len(got.Revoked) != 2 {
		t.Fatalf("nothing new may be published: %+v %v", got, err)
	}
	// Still failing a day later with the clock still wrong; ageing is from the issue time.
	if _, err := admin.Revoke(ctx, nil, issued.Add(-time.Hour)); !errors.Is(err, revocation.ErrFuture) {
		t.Fatal(err)
	}
	for _, g := range []*revocation.Guard{adminGuard, peer.d.Guard} {
		if s := g.Status(issued.Add(7*day - time.Second)); s.Warn || s.Stale {
			t.Fatalf("before 7 days: %+v", s)
		}
		if s := g.Status(issued.Add(7*day + time.Second)); !s.Warn || s.Stale {
			t.Fatalf("after 7 days: %+v", s)
		}
		if s := g.Status(issued.Add(14*day + time.Second)); !s.Warn || !s.Stale {
			t.Fatalf("after 14 days: %+v", s)
		}
		if err := g.CheckSend("x", issued.Add(14*day+time.Second)); !errors.Is(err, revocation.ErrStale) {
			t.Fatal(err)
		}
	}
	// Once the clock is right the next renewal works and the version moves on.
	if s, err := admin.Revoke(ctx, nil, issued.Add(day)); err != nil || s.Version != 3 {
		t.Fatalf("recovered clock: %+v %v", s, err)
	}
}

// A list not signed by the pinned root is never adopted, even if the gateway relays it.
func TestForgedListIsIgnored(t *testing.T) {
	url, tenant := gatewayFor(t)
	ctx := context.Background()
	r, _ := root.New()
	evil, _ := root.New()
	peer := newNode(t, r.Public, url, tenant, "p@acme.test")
	eve, _, _ := adminNode(t, evil, url, tenant)
	if _, err := eve.Revoke(ctx, []string{"victim"}, t0); err != nil {
		t.Fatal(err)
	}
	if err := peer.d.Refresh(ctx, t0); !errors.Is(err, revocation.ErrBadSignature) {
		t.Fatalf("forged list: %v", err)
	}
	if err := peer.d.AuthorizeSend(&binding.Signed{}, t0); err == nil {
		t.Fatal("an empty binding must not be authorized")
	}
	if g := peer.d.Guard.Status(t0); g.Version != 0 {
		t.Fatal("nothing adopted")
	}
}
