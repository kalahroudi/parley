// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package prekey

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestAllocRegionFallbacks(t *testing.T) {
	errMap, errLock := errors.New("map failed"), errors.New("lock failed")
	buf := make([]byte, 64)
	unmapped := 0
	swap(t, &mapRegion, func(int) ([]byte, error) { return buf, nil })
	swap(t, &unmapRegion, func([]byte) { unmapped++ })

	// Lock succeeds: the guarantee is reported.
	swap(t, &lockRegion, func([]byte) error { return nil })
	if _, locked, err := allocRegion(64, false); err != nil || !locked {
		t.Fatalf("locked: %v %v", locked, err)
	}

	// Lock fails: fail closed by default, and release the mapping.
	swap(t, &lockRegion, func([]byte) error { return errLock })
	_, _, err := allocRegion(64, false)
	if !errors.Is(err, ErrNotLocked) || !errors.Is(err, errLock) || unmapped != 1 {
		t.Fatalf("strict: %v unmapped=%d", err, unmapped)
	}

	// Opt-in fallback: usable, and the pool says it is unlocked.
	b, locked, err := allocRegion(64, true)
	if err != nil || locked || len(b) != 64 {
		t.Fatalf("fallback: %v %v", locked, err)
	}

	// Mapping failure passes through.
	swap(t, &mapRegion, func(int) ([]byte, error) { return nil, errMap })
	if _, _, err := allocRegion(64, true); !errors.Is(err, errMap) {
		t.Fatalf("map: %v", err)
	}
}

func TestPoolReportsLockLevel(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	cfg := Config{Signer: priv, Tenant: "t", DeviceID: "d"}
	swap(t, &lockRegion, func([]byte) error { return errors.New("RLIMIT_MEMLOCK") })

	if _, err := New(cfg); !errors.Is(err, ErrNotLocked) {
		t.Fatalf("strict: %v", err)
	}
	cfg.AllowUnlocked = true
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.Locked() {
		t.Fatal("pool claims locked memory")
	}
	// The fallback pool still issues, expires and zeroes.
	s, err := p.Issue(req("c"))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Consume(s.ID); err != nil {
		t.Fatal(err)
	}
}
