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

// The attack: after the check passed and the downloads began, the directory path is repointed (a link swapped) at
// a directory the attacker controls. The writes went to the directory that was checked, and the check before the
// swap sees the change, so nothing lands in the attacker's directory and nothing is replaced.
func TestApplyDirectoryLinkSwappedDuringUpdate(t *testing.T) {
	r := newRelease(t)
	os.Chmod(r.dir, 0o700)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	base := t.TempDir()
	link := filepath.Join(base, "bin")
	if err := os.Symlink(r.dir, link); err != nil {
		t.Fatal(err)
	}
	evil := filepath.Join(base, "evil")
	os.Mkdir(evil, 0o700)
	for _, n := range []string{"parleyd", "parley-cli"} {
		os.WriteFile(filepath.Join(evil, n), []byte("evil"), 0o700)
	}
	u := r.updater("v1.0.0", "")
	u.Dir = link
	rel, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	swapped := false
	u.Source = watchSource{u.Source, func() {
		if !swapped {
			swapped = true
			os.Remove(link)
			os.Symlink(evil, link)
		}
	}}
	if err := u.Apply(context.Background(), rel); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("got %v", err)
	}
	for d, want := range map[string]string{evil: "evil", r.dir: "old"} {
		for _, n := range []string{"parleyd", "parley-cli"} {
			if b, _ := os.ReadFile(filepath.Join(d, n)); string(b) != want && !(want == "old" && string(b) == "old "+n) {
				t.Fatalf("%s/%s is %q", d, n, b)
			}
		}
		if ents, _ := os.ReadDir(d); len(ents) != 2 {
			t.Fatalf("%s: files left behind: %v", d, ents)
		}
	}
	if r.read(t, "parleyd") != "old parleyd" {
		t.Fatal("program replaced")
	}
}

// The attack on a program: after the check passed, it is swapped for a link to a file the attacker controls.
func TestApplyProgramLinkSwappedDuringUpdate(t *testing.T) {
	r := newRelease(t)
	os.Chmod(r.dir, 0o700)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	u := r.updater("v1.0.0", "")
	rel, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "evil")
	os.WriteFile(target, []byte("evil"), 0o700)
	swapped := false
	u.Source = watchSource{u.Source, func() {
		if !swapped {
			swapped = true
			p := filepath.Join(r.dir, "parleyd")
			os.Remove(p)
			os.Symlink(target, p)
		}
	}}
	if err := u.Apply(context.Background(), rel); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("got %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "evil" {
		t.Fatalf("the link target was written: %q", b)
	}
	if r.read(t, "parley-cli") != "old parley-cli" {
		t.Fatal("program replaced")
	}
}
