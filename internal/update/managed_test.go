// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestManaged(t *testing.T) {
	for p, want := range map[string]bool{
		"/opt/homebrew/Cellar/parley/1.0.0/bin/parleyd": true,
		"/home/linuxbrew/.linuxbrew/bin/parleyd":        true,
		"/usr/bin/parleyd":                              true,
		"/usr/sbin/parleyd":                             true,
		"/bin/parleyd":                                  true,
		"/sbin/parleyd":                                 true,
		"/nix/store/abc-parley/bin/parleyd":             true,
		"/snap/parley/1/bin/parleyd":                    true,
		"/usr/local/bin/parleyd":                        false,
		"/home/u/.local/bin/parleyd":                    false,
		"/home/u/usr/bin/parleyd":                       false,
		"C:/Users/u/AppData/Local/Parley/bin/parleyd":   false,
	} {
		if managed(p) != want {
			t.Errorf("%s: managed=%v", p, !want)
		}
	}
}

func TestLocate(t *testing.T) {
	d := t.TempDir()
	real, _ := filepath.EvalSymlinks(d)
	exe := filepath.Join(d, "parleyd")
	os.WriteFile(exe, nil, 0o755)
	got, err := Locate(exe)
	if err != nil || got != real {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := Locate(filepath.Join(d, "nope")); err == nil {
		t.Fatal("missing file accepted")
	}
	// A file inside a package manager's tree is managed (no link needed, so this runs on Windows too).
	tree := filepath.Join(d, "Cellar", "parley", "0.9.0", "bin")
	os.MkdirAll(tree, 0o755)
	os.WriteFile(filepath.Join(tree, "parleyd"), nil, 0o755)
	if _, err := Locate(filepath.Join(tree, "parleyd")); !errors.Is(err, ErrManaged) {
		t.Fatalf("file in a Cellar: %v", err)
	}
	if runtime.GOOS == "windows" {
		return // creating links needs a privilege there
	}
	// A link into a package manager's tree is managed, wherever the link lives.
	cellar := filepath.Join(d, "Cellar", "parley", "1.0.0", "bin")
	os.MkdirAll(cellar, 0o755)
	os.WriteFile(filepath.Join(cellar, "parleyd"), nil, 0o755)
	link := filepath.Join(d, "parleyd-link")
	if err := os.Symlink(filepath.Join(cellar, "parleyd"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := Locate(link); !errors.Is(err, ErrManaged) {
		t.Fatalf("got %v", err)
	}
}
