// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package fsperm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// tempDir returns a short temp directory (unix socket paths elsewhere need it).
func tempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "fp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// privateFile writes a file inside a freshly created private directory.
func privateFile(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(tempDir(t), "p")
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEnsureDirCreatesAndVerifies(t *testing.T) {
	dir := filepath.Join(tempDir(t), "a", "b")
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(dir); err != nil {
		t.Fatalf("created directory fails its own check: %v", err)
	}
	if err := EnsureDir(dir); err != nil {
		t.Fatalf("second call on an existing private dir: %v", err)
	}
}

func TestDirChecksRejectNonDirectoriesAndMissing(t *testing.T) {
	d := tempDir(t)
	f := filepath.Join(d, "f")
	os.WriteFile(f, nil, 0o600)
	if err := CheckDir(f); err == nil {
		t.Error("a file was accepted as a directory")
	}
	if err := CheckDir(filepath.Join(d, "nope")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing directory: %v", err)
	}
	if err := EnsureDir(filepath.Join(f, "sub")); err == nil {
		t.Error("a directory under a file was created")
	}
}

func TestCheckFile(t *testing.T) {
	p := privateFile(t)
	if err := CheckFile(p); err != nil {
		t.Fatalf("private file: %v", err)
	}
	if err := CheckFile(filepath.Dir(p)); err == nil {
		t.Error("a directory was accepted as a key file")
	}
	if err := CheckFile(filepath.Join(filepath.Dir(p), "none")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing file must satisfy ErrNotExist: %v", err)
	}
}

func TestLock(t *testing.T) {
	p := filepath.Join(tempDir(t), "l")
	release, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(p); !errors.Is(err, ErrLocked) {
		t.Errorf("second lock: %v", err)
	}
	release()
	release2, err := Lock(p)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	release2()
	if _, err := Lock(filepath.Join(p, "no", "such")); err == nil || errors.Is(err, ErrLocked) {
		t.Errorf("an unopenable lock file must be an error, not 'locked': %v", err)
	}
}

func TestTryLockOnClosedFile(t *testing.T) {
	f, err := os.Create(filepath.Join(tempDir(t), "c"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := tryLock(f); err == nil || errors.Is(err, ErrLocked) {
		t.Errorf("a closed file must fail as an error, not as 'locked': %v", err)
	}
}
