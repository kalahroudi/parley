// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/root"
)

// Runs the whole user path against a real gateway: sign-in (the browser step is played by
// tests/enroll-cli.test.mjs, which reads the address from this test's output and confirms the code), then
// enrollment, which waits for that test to approve it as the admin. With PARLEY_TEST_GATEWAY_BASE,
// PARLEY_TEST_GATEWAY_TENANT and PARLEY_TEST_ROOT_FP set it runs against that gateway; without them it runs the
// same steps against the in-process fake gateway, so it is never skipped.
func TestAgainstWorker(t *testing.T) {
	base, tenant, fp := os.Getenv("PARLEY_TEST_GATEWAY_BASE"), os.Getenv("PARLEY_TEST_GATEWAY_TENANT"), os.Getenv("PARLEY_TEST_ROOT_FP")
	if base == "" || tenant == "" || fp == "" {
		g := newFakeGateway(t)
		base, tenant, fp = g.srv.URL, "acme", root.Fingerprint(g.rootPub)
	}
	dir := t.TempDir()
	dirs := daemon.Dirs{Config: filepath.Join(dir, "cfg"), State: filepath.Join(dir, "state")}
	sessions := &memSessions{}
	say := func(s string) { fmt.Println(s) }
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Minute)
	defer stop()
	if err := Login(ctx, LoginOptions{Gateway: base, Tenant: tenant, Sessions: sessions, Poll: 100 * time.Millisecond, Progress: say}); err != nil {
		t.Fatal(err)
	}
	if !sessions.has(tenant) {
		t.Fatal("no session after login")
	}
	keys := &memKeys{}
	res, err := Enroll(ctx, Options{
		Dirs: dirs, Gateway: base, Tenant: tenant, RootFingerprint: fp, Name: "worker-test", KeyStore: daemon.KeyStoreFile, Keys: keys,
		Sessions: sessions, Poll: 100 * time.Millisecond, Progress: say,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sessions.has(tenant) || keys.saves != 1 || res.Config.Tenant != tenant {
		t.Fatalf("session kept=%v saves=%d cfg=%+v", sessions.has(tenant), keys.saves, res.Config)
	}
	say("ENROLLED " + res.Config.DeviceID)
}
