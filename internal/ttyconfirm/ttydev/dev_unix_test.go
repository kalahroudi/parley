// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package ttydev

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenPath(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tty")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rw, closeFn, err := openPath(p)
	if err != nil || rw == nil || closeFn == nil {
		t.Fatalf("an openable path: %v", err)
	}
	closeFn()
	if _, _, err := openPath(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a path that cannot be opened was accepted")
	}
}

// Open asks for the process's controlling terminal: it works if there is one and fails if not, and never panics.
func TestOpenControllingTerminal(t *testing.T) {
	if _, closeFn, err := Open(); err == nil {
		closeFn()
	}
}
