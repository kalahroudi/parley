// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || windows

package daemon

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

// The real OS keychain. Built only where one exists (macOS Keychain, Windows
// Credential Manager); Linux CI has no Secret Service, so Linux is covered by
// the file store and the keychain seam. The entry is removed afterwards.
func TestRealKeychain(t *testing.T) {
	id := "parley-test-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	t.Cleanup(func() { keyring.Delete(KeychainService, id) })
	ks := NewKeychainStore(id)
	key, created, err := LoadOrCreate(ks, rand.Reader)
	if err != nil || !created {
		t.Fatal(created, err)
	}
	again, created, err := LoadOrCreate(ks, rand.Reader)
	if err != nil || created || !key.Equal(again) {
		t.Fatalf("keychain round trip: created=%v err=%v", created, err)
	}
}
