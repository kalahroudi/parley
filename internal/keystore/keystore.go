// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package keystore holds the device's long-term Ed25519 signing key seed.
//
// Guarantees, by store. KeychainStore keeps the seed in the OS keychain (macOS
// Keychain, Windows Credential Manager, Linux Secret Service), protected by the
// user's login session: other users cannot read it, other processes of the same
// user can. FileStore keeps it in device.key (mode 0600, owner checked, in a
// private directory; a protected DACL on Windows) with no protection against
// other processes of the same user or against root. Both create a key once and
// never replace one: a corrupt, unreadable or exposed key stops startup, and
// the device must be re-enrolled deliberately. Zeroing in memory is best effort
// (Go gives no guarantee), and key bytes never appear in an error.
package keystore

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kalahroudi/parley/internal/fsperm"
	"github.com/zalando/go-keyring"
)

// ErrNoKey means no device key is stored yet.
var ErrNoKey = errors.New("keystore: no device key stored")

// ErrKeyCorrupt means a stored key exists but is not a valid seed. The daemon
// never replaces it: silently minting a new identity would orphan the device's
// binding and hide a tampering or a keychain fault.
var ErrKeyCorrupt = errors.New("keystore: stored device key is corrupt")

// ErrNotFound is what a Keyring returns for a missing entry.
var ErrNotFound = keyring.ErrNotFound

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
		return nil, false, fmt.Errorf("keystore: generate device key: %w", err)
	}
	if err := ks.Save(key); err != nil {
		Zero(key)
		return nil, false, err
	}
	return key, true, nil
}

// LoadOrCreateLocked is LoadOrCreate with lock held around the creation. Two
// daemons starting together on a first run would otherwise both find no key and
// both mint one, and the keychain keeps only the last write: the loser would
// run under an identity that is stored nowhere. A stored key is returned
// without taking the lock, so a running daemon never blocks it.
func LoadOrCreateLocked(ks KeyStore, rnd io.Reader, lock func() (release func(), err error)) (ed25519.PrivateKey, bool, error) {
	if key, err := ks.Load(); !errors.Is(err, ErrNoKey) {
		return key, false, err
	}
	release, err := lock()
	if err != nil {
		return nil, false, err
	}
	defer release()
	return LoadOrCreate(ks, rnd)
}

// Zero overwrites key material (best effort: Go gives no zeroing guarantee).
func Zero(b []byte) { clear(b) }

func decodeSeed(s []byte) (ed25519.PrivateKey, error) {
	seed := make([]byte, hex.DecodedLen(len(s)))
	n, err := hex.Decode(seed, s)
	defer Zero(seed)
	if err != nil || n != ed25519.SeedSize {
		return nil, ErrKeyCorrupt
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// KeychainService is the service name entries are filed under.
const KeychainService = "parley-device-key"

// Keyring is the OS keychain as KeychainStore uses it.
type Keyring interface {
	Get(service, user string) (string, error) // ErrNotFound when missing
	Set(service, user, secret string) error
}

// KeychainStore keeps the seed in a Keyring under the device id.
type KeychainStore struct {
	Account string // the device id
	KR      Keyring
}

func (k *KeychainStore) Load() (ed25519.PrivateKey, error) {
	s, err := k.KR.Get(KeychainService, k.Account)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNoKey
	}
	if err != nil {
		// The keychain's error text is not logged or wrapped: it can carry
		// service details, and the caller only needs to know it failed.
		return nil, errors.New("keystore: OS keychain unavailable (use key_store \"file\" on headless hosts)")
	}
	return decodeSeed([]byte(s))
}

func (k *KeychainStore) Save(key ed25519.PrivateKey) error {
	if _, err := k.KR.Get(KeychainService, k.Account); err == nil {
		return errors.New("keystore: a device key already exists in the keychain")
	}
	if err := k.KR.Set(KeychainService, k.Account, hex.EncodeToString(key.Seed())); err != nil {
		return errors.New("keystore: could not store the device key in the OS keychain")
	}
	return nil
}

// FileStore keeps the seed in a private file: the explicit opt-in for hosts
// with no keychain (headless pods and CI). The directory is created private and
// the file is checked on every open.
type FileStore struct{ Dir string }

// readFile is a seam so tests can make the read fail after the checks pass.
var readFile = os.ReadFile

// newFile creates the key file exclusively (a seam so tests can make writing fail).
var newFile = func(path string) (keyFile, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	return f, nil
}

type keyFile interface {
	io.Writer
	Sync() error
	Close() error
}

func (f FileStore) path() string { return filepath.Join(f.Dir, "device.key") }

func (f FileStore) Load() (ed25519.PrivateKey, error) {
	if err := fsperm.CheckFile(f.path()); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoKey
		}
		return nil, err
	}
	data, err := readFile(f.path())
	if err != nil {
		return nil, fmt.Errorf("keystore: read device key: %w", err)
	}
	defer Zero(data)
	return decodeSeed(data)
}

func (f FileStore) Save(key ed25519.PrivateKey) error {
	if err := fsperm.EnsureDir(f.Dir); err != nil {
		return err
	}
	w, err := newFile(f.path())
	if err != nil {
		return fmt.Errorf("keystore: create device key file: %w", err)
	}
	enc := make([]byte, hex.EncodedLen(ed25519.SeedSize))
	hex.Encode(enc, key.Seed())
	defer Zero(enc)
	if _, err := w.Write(enc); err != nil {
		w.Close()
		os.Remove(f.path())
		return fmt.Errorf("keystore: write device key: %w", err)
	}
	if err := w.Sync(); err != nil {
		w.Close()
		os.Remove(f.path())
		return fmt.Errorf("keystore: sync device key: %w", err)
	}
	return w.Close()
}
