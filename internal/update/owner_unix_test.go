// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kalahroudi/parley/internal/fsowner"
)

// The real mode bits and owners, end to end through Apply: nothing is replaced in a place others can write.
func TestApplyRefusesUnsafeDirectoriesOnUnix(t *testing.T) {
	unsafe := map[string]func(t *testing.T, r *testRelease){
		"directory writable by group": func(t *testing.T, r *testRelease) { os.Chmod(r.dir, 0o770) },
		"directory writable by all":   func(t *testing.T, r *testRelease) { os.Chmod(r.dir, 0o777) },
		"program writable by group":   func(t *testing.T, r *testRelease) { os.Chmod(filepath.Join(r.dir, "parley-cli"), 0o775) },
		"program is a link": func(t *testing.T, r *testRelease) {
			p := filepath.Join(r.dir, "parleyd")
			os.Rename(p, p+".real")
			if err := os.Symlink(p+".real", p); err != nil {
				t.Fatal(err)
			}
		},
		"world-writable parent without sticky bit": func(t *testing.T, r *testRelease) {
			// r.dir moves under a directory anyone can write and rename entries in.
			open := filepath.Join(t.TempDir(), "open")
			os.Mkdir(open, 0o700)
			os.Chmod(open, 0o777)
			moved := filepath.Join(open, "bin")
			if err := os.Rename(r.dir, moved); err != nil {
				t.Fatal(err)
			}
			r.dir = moved
		},
	}
	for name, setup := range unsafe {
		r := newRelease(t)
		os.Chmod(r.dir, 0o700)
		r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
		setup(t, r)
		if _, err := r.updater("v1.0.0", "").Update(context.Background()); !errors.Is(err, ErrNotOwner) {
			t.Errorf("%s: got %v", name, err)
		}
		if b, _ := os.ReadFile(filepath.Join(r.dir, "parley-cli")); string(b) != "old parley-cli" {
			t.Errorf("%s: parley-cli changed: %q", name, b)
		}
	}
}

// A sticky world-writable parent (like /tmp) is fine: nobody else can rename our directory away.
func TestApplyAllowsStickyParentOnUnix(t *testing.T) {
	r := newRelease(t)
	os.Chmod(r.dir, 0o700)
	sticky := filepath.Join(t.TempDir(), "sticky")
	os.Mkdir(sticky, 0o700)
	os.Chmod(sticky, 0o777|os.ModeSticky)
	moved := filepath.Join(sticky, "bin")
	if err := os.Rename(r.dir, moved); err != nil {
		t.Fatal(err)
	}
	r.dir = moved
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	if _, err := r.updater("v1.0.0", "").Update(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Another user's directory: the filesystem root is owned by root, so a process that is not root must refuse it
// as an install directory, and a root process (which is the owner) must not.
func TestCheckInstallRefusesDirectoryOfAnotherUserOnUnix(t *testing.T) {
	err := checkInstall("/", nil, fsowner.Inspect)
	if os.Geteuid() == 0 {
		if err != nil {
			t.Fatalf("root owns /: %v", err)
		}
		return
	}
	if !errors.Is(err, ErrNotOwner) {
		t.Fatalf("got %v", err)
	}
}
