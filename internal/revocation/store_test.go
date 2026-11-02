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
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
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
