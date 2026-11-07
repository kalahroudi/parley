// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package root

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrExists is returned when a root key is already stored.
var ErrExists = errors.New("root: a root key already exists here")

// Store keeps the root key seed on this device.
type Store interface {
	Exists() (bool, error)
	Save(priv ed25519.PrivateKey) error
}

// FileStore keeps the seed in a 0600 file in a 0700 directory. An OS keychain
// store (macOS, Windows, Linux) is a drop-in replacement for this interface;
// until then the file is the documented fallback.
type FileStore struct{ Dir string }

func (s FileStore) path() string { return filepath.Join(s.Dir, "root.key") }

func (s FileStore) Exists() (bool, error) {
	_, err := os.Stat(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Seams so tests can force a failure at each step of Save.
var (
	syncFile   = func(f *os.File) error { return f.Sync() }
	createTemp = os.CreateTemp
	link       = os.Link
)

// Save writes the seed to a temp file, syncs it, then hard-links it into place.
// The link fails if root.key exists, so nothing is overwritten, and a failure
// at any step leaves no partial root.key and no temp file behind.
func (s FileStore) Save(priv ed25519.PrivateKey) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	f, err := createTemp(s.Dir, ".root.key.*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(priv.Seed()); err != nil {
		f.Close()
		return fmt.Errorf("root: write key: %w", err)
	}
	if err := syncFile(f); err != nil {
		f.Close()
		return fmt.Errorf("root: sync key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("root: write key: %w", err)
	}
	if err := link(tmp, s.path()); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return err
	}
	return nil
}

// ErrNoRoot is returned when no root key is stored.
var ErrNoRoot = errors.New("root: no root key stored here")

// Load reads the root key back. Only the local signer uses it.
func (s FileStore) Load() (ed25519.PrivateKey, error) {
	seed, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoRoot
	}
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("root: stored key has the wrong length")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
