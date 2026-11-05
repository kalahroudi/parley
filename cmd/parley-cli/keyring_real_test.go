// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/kalahroudi/parley/internal/enroll"
)

// The real OS keychain, through the session store. Built only where one exists; the entry is removed afterwards.
func TestRealKeychainSessions(t *testing.T) {
	var suffix [6]byte
	rand.Read(suffix[:])
	tenant := "parley-test-" + hex.EncodeToString(suffix[:])
	s := enroll.KeyringSessions{KR: OSKeyring{}}
	t.Cleanup(func() { s.Clear(tenant) })
	if _, err := s.Load(tenant); !errors.Is(err, enroll.ErrNoSession) {
		t.Fatalf("empty: %v", err)
	}
	tok := "ps_" + tenant + "." + strings.Repeat("0", 64)
	if err := s.Save(tenant, tok); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Load(tenant); err != nil || got != tok {
		t.Fatalf("round trip: %q %v", got, err)
	}
	if err := s.Clear(tenant); err != nil {
		t.Fatal(err)
	}
	if err := s.Clear(tenant); err != nil {
		t.Fatalf("clearing nothing: %v", err)
	}
}
