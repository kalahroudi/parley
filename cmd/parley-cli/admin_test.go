// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kalahroudi/parley/internal/root"
)

func TestAdminInit(t *testing.T) {
	dir := t.TempDir()
	store := root.FileStore{Dir: filepath.Join(dir, "cfg")}
	backup := filepath.Join(dir, "cfg", "b.json")
	var out, errw bytes.Buffer
	if code := adminInit(nil, &out, &errw, store, backup); code != 0 {
		t.Fatalf("exit %d: %s", code, errw.String())
	}
	m := regexp.MustCompile(`Recovery code: (\S+)`).FindStringSubmatch(out.String())
	if m == nil || !strings.Contains(out.String(), "Fingerprint: ") {
		t.Fatalf("output: %s", out.String())
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Recover(m[1], data); err != nil {
		t.Fatal(err)
	}
	// Second run refuses and does not touch the backup.
	out.Reset()
	errw.Reset()
	if code := adminInit(nil, &out, &errw, store, backup); code != 1 || !strings.Contains(errw.String(), "already exists") || out.Len() != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out.String(), errw.String())
	}
}

type failStore struct{ exists, saveErr error }

func (f failStore) Exists() (bool, error)           { return false, f.exists }
func (f failStore) Save(_ ed25519.PrivateKey) error { return f.saveErr }

func TestAdminInitErrors(t *testing.T) {
	dir := t.TempDir()
	var out, errw bytes.Buffer
	if adminInit([]string{"-nope"}, &out, &errw, root.FileStore{Dir: dir}, "") != 2 {
		t.Fatal("bad flag")
	}
	if adminInit(nil, &out, &errw, failStore{exists: os.ErrPermission}, "") != 1 {
		t.Fatal("exists error")
	}
	// Backup path under a regular file: mkdir fails.
	f := filepath.Join(dir, "f")
	os.WriteFile(f, nil, 0o600)
	if adminInit(nil, &out, &errw, failStore{}, filepath.Join(f, "x", "b.json")) != 1 {
		t.Fatal("mkdir")
	}
	// Backup path is a directory: write fails.
	if adminInit(nil, &out, &errw, failStore{}, dir) != 1 {
		t.Fatal("write")
	}
	// Save fails: backup is removed, nothing printed.
	b := filepath.Join(dir, "b.json")
	out.Reset()
	if adminInit([]string{"-backup", b}, &out, &errw, failStore{saveErr: os.ErrPermission}, "") != 1 {
		t.Fatal("save")
	}
	if _, err := os.Stat(b); err == nil || out.Len() != 0 {
		t.Fatal("backup left behind or code printed")
	}
	// Save loses a race with another init.
	if adminInit([]string{"-backup", b}, &out, &errw, failStore{saveErr: root.ErrExists}, "") != 1 {
		t.Fatal("race")
	}
}
