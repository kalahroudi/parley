// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateDirRejectsOtherOwner(t *testing.T) {
	dir := filepath.Join(shortTemp(t), "own")
	os.Mkdir(dir, 0o700)
	old := geteuid
	geteuid = func() int { return old() + 1 }
	defer func() { geteuid = old }()
	if err := checkPrivateDir(dir); err == nil {
		t.Error("a directory owned by someone else was accepted")
	}
}

func TestPrivateDirRejectsSymlink(t *testing.T) {
	d := shortTemp(t)
	target := filepath.Join(d, "t")
	os.Mkdir(target, 0o700)
	link := filepath.Join(d, "l")
	os.Symlink(target, link)
	if err := checkPrivateDir(link); err == nil {
		t.Error("a symlinked directory was accepted")
	}
}
