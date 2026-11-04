// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package keystore

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreRefusesAnExposedKeyFile(t *testing.T) {
	dir := filepath.Join(tempDir(t), "cfg")
	fs := FileStore{Dir: dir}
	if _, _, err := LoadOrCreate(fs, rand.Reader); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "device.key")
	os.Chmod(p, 0o640)
	if _, err := fs.Load(); err == nil || errors.Is(err, ErrNoKey) || errors.Is(err, ErrKeyCorrupt) {
		t.Errorf("a group-readable key file must be refused, not read or replaced: %v", err)
	}
	os.Chmod(p, 0o600)
	if _, err := fs.Load(); err != nil {
		t.Errorf("0600 key file: %v", err)
	}
	// A symlink to a valid key is not followed.
	os.Rename(p, filepath.Join(dir, "real"))
	os.Symlink(filepath.Join(dir, "real"), p)
	if _, err := fs.Load(); err == nil || errors.Is(err, ErrNoKey) {
		t.Errorf("a symlinked key file must be refused: %v", err)
	}
}
