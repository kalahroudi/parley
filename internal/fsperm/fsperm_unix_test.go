// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package fsperm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDirRejectsOpenDirectory(t *testing.T) {
	dir := filepath.Join(tempDir(t), "open")
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o750)
	if err := CheckDir(dir); err == nil {
		t.Error("a group-accessible directory was accepted")
	}
	if err := EnsureDir(dir); err == nil {
		t.Error("EnsureDir must not accept it either")
	}
	os.Chmod(dir, 0o707)
	if err := CheckDir(dir); err == nil {
		t.Error("an other-accessible directory was accepted")
	}
}

func withOtherEuid(t *testing.T) {
	t.Helper()
	old := geteuid
	geteuid = func() int { return old() + 1 }
	t.Cleanup(func() { geteuid = old })
}

func TestCheckRejectsOtherOwner(t *testing.T) {
	p := privateFile(t)
	withOtherEuid(t)
	if err := CheckDir(filepath.Dir(p)); err == nil {
		t.Error("a directory owned by someone else was accepted")
	}
	if err := CheckFile(p); err == nil {
		t.Error("a file owned by someone else was accepted")
	}
}

func TestCheckRejectsSymlinks(t *testing.T) {
	p := privateFile(t)
	d := filepath.Dir(p)
	link := filepath.Join(d, "l")
	os.Symlink(d, link)
	if err := CheckDir(link); err == nil {
		t.Error("a symlinked directory was accepted")
	}
	flink := filepath.Join(d, "fl")
	os.Symlink(p, flink)
	if err := CheckFile(flink); err == nil {
		t.Error("a symlinked file was accepted")
	}
}

func TestCheckFileRejectsExposedMode(t *testing.T) {
	p := privateFile(t)
	for _, m := range []os.FileMode{0o640, 0o604, 0o660, 0o666} {
		os.Chmod(p, m)
		if err := CheckFile(p); err == nil {
			t.Errorf("mode %o was accepted", m)
		}
	}
	os.Chmod(p, 0o400)
	if err := CheckFile(p); err != nil {
		t.Errorf("mode 0400: %v", err)
	}
}
