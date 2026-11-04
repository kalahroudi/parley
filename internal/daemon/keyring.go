// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import "github.com/zalando/go-keyring"

// osKeyring is the real OS keychain (macOS Keychain, Windows Credential
// Manager, Linux Secret Service) behind keystore.KeychainStore.
type osKeyring struct{}

//cover:ignore thin call into the real OS keychain, exercised by the keychain integration test on macOS and Windows (keychain_real_test.go)
func (osKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }

//cover:ignore thin call into the real OS keychain, exercised by the keychain integration test on macOS and Windows (keychain_real_test.go)
func (osKeyring) Set(service, user, secret string) error { return keyring.Set(service, user, secret) }
