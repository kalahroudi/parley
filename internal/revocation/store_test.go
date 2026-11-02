// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package revocation

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileStoreRoundTrip(t *testing.T) {
	_, priv := keys(t)
	path := filepath.Join(t.TempDir(), "r.json")
	st := NewFileStore(path)
	if s, err := st.Load(); s != nil || err != nil {
		t.Fatal(s, err)
	}
	want := signed(t, priv, 3, now, "a", "b")
	if err := st.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load()
	if err != nil || string(got.Encode()) != string(want.Encode()) || string(got.Signature) != string(want.Signature) {
		t.Fatal(got, err)
	}
	if fi, _ := os.Stat(path); goos != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestFileStoreLoadErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.json")
	st := NewFileStore(path)
	for name, body := range map[string]string{
		"garbage":  "nope",
		"unknown":  `{"tenant":"t","version":1,"issued_at":"2026-01-01T00:00:00Z","revoked":[],"signature":"","x":1}`,
		"trailing": `{"tenant":"t"} {}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Load(); !errors.Is(err, ErrStore) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A directory where the file should be is a read error, not "never saved".
	if _, err := NewFileStore(dir).Load(); !errors.Is(err, ErrStore) {
		t.Fatal(err)
	}
}

func TestFileStoreSaveErrors(t *testing.T) {
	_, priv := keys(t)
	s := signed(t, priv, 1, now)
	dir := t.TempDir()
	if err := NewFileStore(filepath.Join(dir, "missing", "r.json")).Save(s); !errors.Is(err, ErrStore) {
		t.Fatal("no parent dir:", err)
	}
	st := NewFileStore(filepath.Join(dir, "r.json"))
	st.rename = func(string, string) error { return errors.New("rename failed") }
	if err := st.Save(s); !errors.Is(err, ErrStore) {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.tmp*"))
	if len(left) != 0 {
		t.Fatal("temp file left behind:", left)
	}
	if _, err := os.Stat(filepath.Join(dir, "r.json")); !os.IsNotExist(err) {
		t.Fatal("failed save must not create the file")
	}
}

type fakeTmp struct {
	*os.File
	failWrite, failSync, failClose bool
}

func (f *fakeTmp) Write(p []byte) (int, error) {
	if f.failWrite {
		return 0, errors.New("write failed")
	}
	return f.File.Write(p)
}

func (f *fakeTmp) Sync() error {
	if f.failSync {
		return errors.New("sync failed")
	}
	return f.File.Sync()
}

func (f *fakeTmp) Close() error {
	err := f.File.Close()
	if f.failClose {
		return errors.New("close failed")
	}
	return err
}

// Every step of Save that can fail must report ErrStore, leave no temp file
// and leave an existing saved list untouched.
func TestFileStoreSaveStepFailures(t *testing.T) {
	_, priv := keys(t)
	old, next := signed(t, priv, 1, now, "a"), signed(t, priv, 2, now, "a", "b")
	steps := map[string]func(st *FileStore){
		"write": func(st *FileStore) {
			st.create = func(d, p string) (tmpFile, error) {
				f, err := os.CreateTemp(d, p)
				return &fakeTmp{File: f, failWrite: true}, err
			}
		},
		"sync": func(st *FileStore) {
			st.create = func(d, p string) (tmpFile, error) {
				f, err := os.CreateTemp(d, p)
				return &fakeTmp{File: f, failSync: true}, err
			}
		},
		"close": func(st *FileStore) {
			st.create = func(d, p string) (tmpFile, error) {
				f, err := os.CreateTemp(d, p)
				return &fakeTmp{File: f, failClose: true}, err
			}
		},
		"dir sync": func(st *FileStore) { st.syncDir = func(string) error { return errors.New("dir sync failed") } },
	}
	for name, breakIt := range steps {
		dir := t.TempDir()
		st := NewFileStore(filepath.Join(dir, "r.json"))
		if err := st.Save(old); err != nil {
			t.Fatal(err)
		}
		breakIt(st)
		if err := st.Save(next); !errors.Is(err, ErrStore) {
			t.Errorf("%s: %v", name, err)
		}
		if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp*")); len(left) != 0 {
			t.Errorf("%s: temp file left behind: %v", name, left)
		}
		got, err := NewFileStore(filepath.Join(dir, "r.json")).Load()
		if err != nil || got == nil {
			t.Fatalf("%s: %v", name, err)
		}
		// A failed directory sync happens after the rename, so the new list is
		// already in place; every earlier failure must leave the old one.
		want := old
		if name == "dir sync" {
			want = next
		}
		if got.Version != want.Version {
			t.Errorf("%s: saved version %d, want %d", name, got.Version, want.Version)
		}
	}
}

func TestSyncDir(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := syncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("a missing directory must be an error")
		}
	}
	defer func(g string) { goos = g }(goos)
	goos = "windows"
	if err := syncDir(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatal("windows skips directory sync:", err)
	}
}
