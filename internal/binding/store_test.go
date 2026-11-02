// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTrackerPersistsAcrossRestart(t *testing.T) {
	rpub, rpriv := keys(t)
	path := filepath.Join(t.TempDir(), "seen.json")
	tr, err := NewTracker(rpub, NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	b2 := sample(t, 2)
	v2, _ := Sign(rpriv, b2)
	b1 := b2
	b1.Version = 1
	v1, _ := Sign(rpriv, b1)
	if err := tr.Accept(v2, now); err != nil {
		t.Fatal(err)
	}

	// "Restart": a new Tracker over the same file.
	tr2, err := NewTracker(rpub, NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := tr2.Accept(v1, now); !errors.Is(err, ErrRollback) {
		t.Fatalf("old binding after restart: %v", err)
	}
	if err := tr2.Accept(v2, now); err != nil {
		t.Fatal("same binding after restart:", err)
	}
	other := b2
	other.SigningKey, _ = keys(t)
	conflict, _ := Sign(rpriv, other)
	if err := tr2.Accept(conflict, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict after restart: %v", err)
	}
	b3 := b2
	b3.Version = 3
	v3, _ := Sign(rpriv, b3)
	if err := tr2.Accept(v3, now); err != nil {
		t.Fatal(err)
	}
	tr3, _ := NewTracker(rpub, NewFileStore(path))
	if err := tr3.Accept(v2, now); !errors.Is(err, ErrRollback) {
		t.Fatalf("v3 not persisted: %v", err)
	}
	if runtime.GOOS != "windows" { // Windows has no POSIX modes
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", fi.Mode().Perm())
		}
	}
}

func TestCorruptStoreFailsClosed(t *testing.T) {
	rpub, _ := keys(t)
	for name, content := range map[string]string{
		"empty":       "",
		"garbage":     "not json",
		"truncated":   `{"format":1,"records":[{"tenant":"t1","device_id":"d1","ver`,
		"bad format":  `{"format":2,"records":[]}`,
		"zero ver":    `{"format":1,"records":[{"tenant":"t","device_id":"d","version":0,"encoded":"AQ=="}]}`,
		"duplicate":   `{"format":1,"records":[{"tenant":"t","device_id":"d","version":1,"encoded":"AQ=="},{"tenant":"t","device_id":"d","version":2,"encoded":"AQ=="}]}`,
		"unknown key": `{"format":1,"records":[],"x":1}`,
		"trailing":    `{"format":1,"records":[]} {}`,
	} {
		path := filepath.Join(t.TempDir(), "seen.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewTracker(rpub, NewFileStore(path)); !errors.Is(err, ErrStore) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// A directory where the file should be is unreadable, not "empty".
	if _, err := NewTracker(rpub, NewFileStore(t.TempDir())); !errors.Is(err, ErrStore) {
		t.Errorf("unreadable: %v", err)
	}
	// Missing file is a first run, not corruption.
	if _, err := NewTracker(rpub, NewFileStore(filepath.Join(t.TempDir(), "none.json"))); err != nil {
		t.Errorf("missing file: %v", err)
	}
}

func TestUnwritableStoreRejectsAccept(t *testing.T) {
	rpub, rpriv := keys(t)
	// Parent directory does not exist, so every write fails.
	path := filepath.Join(t.TempDir(), "missing-dir", "seen.json")
	tr, err := NewTracker(rpub, NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := Sign(rpriv, sample(t, 1))
	if err := tr.Accept(s, now); !errors.Is(err, ErrStore) {
		t.Fatalf("got %v", err)
	}
	// Nothing was recorded in memory either: once writable, it succeeds and a
	// lower version is not wrongly judged against a phantom record.
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := tr.Accept(s, now); err != nil {
		t.Fatal(err)
	}
}

func TestFailedWriteLeavesNoTruncatedFile(t *testing.T) {
	rpub, rpriv := keys(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "seen.json")
	fs := NewFileStore(path)
	tr, _ := NewTracker(rpub, fs)
	b := sample(t, 1)
	v1, _ := Sign(rpriv, b)
	if err := tr.Accept(v1, now); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	fs.rename = func(string, string) error { return errors.New("injected rename failure") }
	b.Version = 2
	v2, _ := Sign(rpriv, b)
	if err := tr.Accept(v2, now); !errors.Is(err, ErrStore) {
		t.Fatalf("got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("store changed by failed write: %v %q", err, after)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 { // the store and its lock file
		t.Fatalf("temp file left behind: %v", ents)
	}
	// The failed v2 was not recorded in memory: v1 is still the highest.
	fs.rename = os.Rename
	if err := tr.Accept(v1, now); err != nil {
		t.Fatal(err)
	}
	if err := tr.Accept(v2, now); err != nil {
		t.Fatal(err)
	}
}
