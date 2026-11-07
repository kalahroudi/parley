// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package fsowner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectModesAndOwner(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "f")
	os.WriteFile(f, nil, 0o600)
	for mode, want := range map[os.FileMode]Info{
		0o700:                 {IsDir: true, Owned: true},
		0o750:                 {IsDir: true, Owned: true},
		0o720:                 {IsDir: true, Owned: true, GroupOrOtherWrite: true},
		0o702:                 {IsDir: true, Owned: true, GroupOrOtherWrite: true, WorldWrite: true},
		0o777:                 {IsDir: true, Owned: true, GroupOrOtherWrite: true, WorldWrite: true},
		0o777 | os.ModeSticky: {IsDir: true, Owned: true, GroupOrOtherWrite: true, WorldWrite: true, Sticky: true},
	} {
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		got, err := Inspect(d)
		if err != nil || got != want {
			t.Errorf("mode %v: got %+v %v, want %+v", mode, got, err, want)
		}
	}
	os.Chmod(d, 0o700)
	if got, _ := Inspect(f); got != (Info{IsRegular: true, Owned: true}) {
		t.Errorf("file: %+v", got)
	}
	os.Chmod(f, 0o664)
	if got, _ := Inspect(f); !got.GroupOrOtherWrite || got.WorldWrite {
		t.Errorf("group-writable file: %+v", got)
	}
}

// A link is reported as a link (not a regular file), never followed.
func TestInspectDoesNotFollowLinks(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "t")
	os.WriteFile(target, nil, 0o600)
	link := filepath.Join(d, "l")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	got, err := Inspect(link)
	if err != nil || got.IsRegular || got.IsDir {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := Inspect(filepath.Join(d, "missing")); err == nil {
		t.Fatal("missing path accepted")
	}
}

// The root directory belongs to root: trusted as a parent, and owned only by a process running as root.
func TestInspectRootDirectory(t *testing.T) {
	got, err := Inspect("/")
	if err != nil || !got.IsDir || !got.Trusted || got.Owned != (os.Geteuid() == 0) {
		t.Fatalf("%+v %v (euid %d)", got, err, os.Geteuid())
	}
}
