// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || windows

package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/kalahroudi/parley/internal/keystore"
	"github.com/zalando/go-keyring"
)

// The real OS keychain. Built only where one exists (macOS Keychain, Windows
// Credential Manager); Linux CI has no Secret Service, so Linux is covered by
// the file store and the keychain seam. The entry is removed afterwards.
func TestRealKeychain(t *testing.T) {
	var suffix [6]byte
	rand.Read(suffix[:])
	// Unique per run, so two jobs on one machine never share an entry.
	id := "parley-test-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) + "-" + hex.EncodeToString(suffix[:])
	t.Cleanup(func() { keyring.Delete(keystore.KeychainService, id) })
	ks := &keystore.KeychainStore{Account: id, KR: osKeyring{}}
	key, created, err := keystore.LoadOrCreate(ks, rand.Reader)
	if err != nil || !created {
		t.Fatal(created, err)
	}
	again, created, err := keystore.LoadOrCreate(ks, rand.Reader)
	if err != nil || created || !key.Equal(again) {
		t.Fatalf("keychain round trip: created=%v err=%v", created, err)
	}
}
