// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateDirCreatedAndVerified(t *testing.T) {
	dir := filepath.Join(shortTemp(t), "a", "b")
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatalf("second call on an existing private dir: %v", err)
	}
}

func TestPrivateDirRejectsOpenDirectory(t *testing.T) {
	dir := filepath.Join(shortTemp(t), "open")
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		// Grant Everyone access: the check must fail.
		if out, err := exec.Command("icacls", dir, "/grant", "*S-1-1-0:(OI)(CI)F").CombinedOutput(); err != nil {
			t.Fatalf("icacls: %v %s", err, out)
		}
	} else if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(dir); err == nil {
		t.Error("a directory open to other users was accepted")
	}
}

func TestPrivateDirRejectsNonDirectoriesAndMissing(t *testing.T) {
	d := shortTemp(t)
	f := filepath.Join(d, "f")
	os.WriteFile(f, nil, 0o600)
	if err := checkPrivateDir(f); err == nil && runtime.GOOS != "windows" {
		t.Error("a file was accepted as a directory")
	}
	if err := checkPrivateDir(filepath.Join(d, "nope")); err == nil {
		t.Error("a missing directory was accepted")
	}
	if err := ensurePrivateDir(filepath.Join(f, "sub")); err == nil {
		t.Error("a directory under a file was created")
	}
}

func TestInstanceLock(t *testing.T) {
	p := filepath.Join(shortTemp(t), "l")
	f1, _ := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	f2, _ := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	defer f1.Close()
	defer f2.Close()
	if ok, err := tryLockFile(f1); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, err := tryLockFile(f2); ok || err != nil {
		t.Errorf("second lock: %v %v", ok, err)
	}
	f1.Close()
	if ok, err := tryLockFile(f2); !ok || err != nil {
		t.Errorf("lock not released on close: %v %v", ok, err)
	}
	if ok, err := tryLockFile(f1); ok || err == nil {
		t.Errorf("a closed file must error: %v %v", ok, err)
	}
}
