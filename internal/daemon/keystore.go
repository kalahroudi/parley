// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

// ErrNoKey means no device key is stored yet.
var ErrNoKey = errors.New("daemon: no device key stored")

// ErrKeyCorrupt means a stored key exists but is not a valid seed. The daemon
// never replaces it: silently minting a new identity would orphan the device's
// binding and hide a tampering or a keychain fault.
var ErrKeyCorrupt = errors.New("daemon: stored device key is corrupt")

// KeyStore holds the device's long-term Ed25519 signing key seed.
type KeyStore interface {
	// Load returns ErrNoKey when nothing is stored.
	Load() (ed25519.PrivateKey, error)
	// Save stores a new key and fails if one already exists.
	Save(ed25519.PrivateKey) error
}

// LoadOrCreate returns the stored key, generating and storing one on first
// run. A store failure other than ErrNoKey stops startup.
func LoadOrCreate(ks KeyStore, rnd io.Reader) (key ed25519.PrivateKey, created bool, err error) {
	key, err = ks.Load()
	if err == nil {
		return key, false, nil
	}
	if !errors.Is(err, ErrNoKey) {
		return nil, false, err
	}
	_, key, err = ed25519.GenerateKey(rnd)
	if err != nil {
		return nil, false, fmt.Errorf("daemon: generate device key: %w", err)
	}
	if err := ks.Save(key); err != nil {
		zero(key)
		return nil, false, err
	}
	return key, true, nil
}

// zero overwrites key material (best effort: Go gives no zeroing guarantee).
func zero(b []byte) { clear(b) }

func decodeSeed(s string) (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(s)
	if err != nil || len(seed) != ed25519.SeedSize {
		zero(seed)
		return nil, ErrKeyCorrupt
	}
	k := ed25519.NewKeyFromSeed(seed)
	zero(seed)
	return k, nil
}

// kring is the part of go-keyring that KeychainStore uses; tests replace it.
type kring struct {
	get func(service, user string) (string, error)
	set func(service, user, secret string) error
}

var osKeyring = kring{get: keyringGet, set: keyringSet}

//cover:ignore thin call into the real OS keychain, exercised by the keychain integration test on macOS and Windows (PARLEY_KEYCHAIN_TEST=1)
func keyringGet(service, user string) (string, error) { return keyring.Get(service, user) }

//cover:ignore thin call into the real OS keychain, exercised by the keychain integration test on macOS and Windows (PARLEY_KEYCHAIN_TEST=1)
func keyringSet(service, user, secret string) error { return keyring.Set(service, user, secret) }

// KeychainService is the service name entries are filed under.
const KeychainService = "parley-device-key"

// KeychainStore keeps the seed in the OS keychain (macOS Keychain, Windows
// Credential Manager, Linux Secret Service), under the device id.
type KeychainStore struct {
	Account string // the device id
	kr      kring
}

// NewKeychainStore returns a store for the device id.
func NewKeychainStore(deviceID string) *KeychainStore {
	return &KeychainStore{Account: deviceID, kr: osKeyring}
}

func (k *KeychainStore) Load() (ed25519.PrivateKey, error) {
	s, err := k.kr.get(KeychainService, k.Account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNoKey
	}
	if err != nil {
		// The keychain's error text is not logged or wrapped: it can carry
		// service details, and the caller only needs to know it failed.
		return nil, errors.New("daemon: OS keychain unavailable (use key_store \"file\" on headless hosts)")
	}
	return decodeSeed(s)
}

func (k *KeychainStore) Save(key ed25519.PrivateKey) error {
	if _, err := k.kr.get(KeychainService, k.Account); err == nil {
		return errors.New("daemon: a device key already exists in the keychain")
	}
	seed := hex.EncodeToString(key.Seed())
	if err := k.kr.set(KeychainService, k.Account, seed); err != nil {
		return errors.New("daemon: could not store the device key in the OS keychain")
	}
	return nil
}

// FileKeyStore keeps the seed in a 0600 file in a private directory. It is the
// explicit opt-in for hosts with no keychain (headless pods and CI); the
// directory is created private and checked on every open.
type FileKeyStore struct{ Dir string }

func (f FileKeyStore) path() string { return filepath.Join(f.Dir, "device.key") }

func (f FileKeyStore) Load() (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(f.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, fmt.Errorf("daemon: read device key: %w", err)
	}
	return decodeSeed(string(data))
}

func (f FileKeyStore) Save(key ed25519.PrivateKey) error {
	if err := ensurePrivateDir(f.Dir); err != nil {
		return err
	}
	w, err := os.OpenFile(f.path(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("daemon: create device key file: %w", err)
	}
	if _, err := w.WriteString(hex.EncodeToString(key.Seed())); err != nil {
		w.Close()
		os.Remove(f.path())
		return fmt.Errorf("daemon: write device key: %w", err)
	}
	if err := w.Sync(); err != nil {
		w.Close()
		os.Remove(f.path())
		return fmt.Errorf("daemon: sync device key: %w", err)
	}
	return w.Close()
}
