// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"

	"github.com/kalahroudi/parley/internal/enroll"
	"github.com/zalando/go-keyring"
)

// OSKeyring is the real OS keychain, for enroll.KeyringSessions (macOS Keychain, Windows Credential
// Manager, Linux Secret Service).
type OSKeyring struct{}

//cover:ignore thin call into the real OS keychain, exercised by the keychain integration test on macOS and Windows (keyring_real_test.go)
func (OSKeyring) Get(service, user string) (string, error) {
	s, err := keyring.Get(service, user)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", enroll.ErrKeyringNotFound
	}
	return s, err
}

//cover:ignore thin call into the real OS keychain, exercised by the keychain integration test on macOS and Windows (keyring_real_test.go)
func (OSKeyring) Set(service, user, secret string) error { return keyring.Set(service, user, secret) }

//cover:ignore thin call into the real OS keychain, exercised by the keychain integration test on macOS and Windows (keyring_real_test.go)
func (OSKeyring) Delete(service, user string) error {
	err := keyring.Delete(service, user)
	if errors.Is(err, keyring.ErrNotFound) {
		return enroll.ErrKeyringNotFound
	}
	return err
}
