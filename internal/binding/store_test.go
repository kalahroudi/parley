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

// failingFile fails the named step of Save's temp-file handling.
type failingFile struct {
	tempFile
	failWrite, failSync, failClose bool
}

func (f failingFile) Write(b []byte) (int, error) {
	if f.failWrite {
		return 0, errors.New("injected write failure")
	}
	return f.tempFile.Write(b)
}

func (f failingFile) Sync() error {
	if f.failSync {
		return errors.New("injected sync failure")
	}
	return f.tempFile.Sync()
}

func (f failingFile) Close() error {
	err := f.tempFile.Close()
	if f.failClose {
		return errors.New("injected close failure")
	}
	return err
}

// Every step of Save fails closed with ErrStore, leaves no temp file, and leaves
// the previous store contents alone.
func TestSaveFailsClosedAtEveryStep(t *testing.T) {
	recs := []Record{{Tenant: "t", DeviceID: "d", Version: 1, Encoded: []byte{1}}}
	steps := map[string]func(*FileStore){
		"marshal": func(f *FileStore) { f.marshal = func(any) ([]byte, error) { return nil, errors.New("injected") } },
		"create": func(f *FileStore) {
			f.create = func(string, string) (tempFile, error) { return nil, errors.New("injected") }
		},
		"write": func(f *FileStore) { wrapTemp(f, failingFile{failWrite: true}) },
		"sync":  func(f *FileStore) { wrapTemp(f, failingFile{failSync: true}) },
		"close": func(f *FileStore) { wrapTemp(f, failingFile{failClose: true}) },
	}
	for name, inject := range steps {
		dir := t.TempDir()
		fs := NewFileStore(filepath.Join(dir, "seen.json"))
		if err := fs.Save(recs); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(fs.path)
		inject(fs)
		bad := []Record{{Tenant: "t", DeviceID: "d", Version: 2, Encoded: []byte{2}}}
		if err := fs.Save(bad); !errors.Is(err, ErrStore) {
			t.Errorf("%s: got %v", name, err)
		}
		if after, _ := os.ReadFile(fs.path); string(after) != string(before) {
			t.Errorf("%s: store changed by a failed write", name)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 1 {
			t.Errorf("%s: temp file left behind: %v", name, ents)
		}
	}
}

// A failed directory sync is reported (the rename has happened by then, so only
// the temp file's absence is checked).
func TestSaveReportsDirSyncFailure(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStore(filepath.Join(dir, "seen.json"))
	fs.syncDir = func(string) error { return errors.New("injected") }
	if err := fs.Save(nil); !errors.Is(err, ErrStore) {
		t.Fatalf("got %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("temp file left behind: %v", ents)
	}
}

func wrapTemp(f *FileStore, w failingFile) {
	f.create = func(dir, pattern string) (tempFile, error) {
		t, err := createTemp(dir, pattern)
		w.tempFile = t
		return w, err
	}
}

// Records of several tenants are written sorted by tenant, then device.
func TestSaveSortsByTenantThenDevice(t *testing.T) {
	fs := NewFileStore(filepath.Join(t.TempDir(), "seen.json"))
	mk := func(tn, d string) Record { return Record{Tenant: tn, DeviceID: d, Version: 1, Encoded: []byte{1}} }
	if err := fs.Save([]Record{mk("b", "1"), mk("a", "2"), mk("a", "1")}); err != nil {
		t.Fatal(err)
	}
	got, err := fs.Load()
	if err != nil || len(got) != 3 || got[0].Tenant != "a" || got[0].DeviceID != "1" || got[1].DeviceID != "2" || got[2].Tenant != "b" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestSyncDirReportsAMissingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directories cannot be synced on Windows")
	}
	if err := syncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("want an error")
	}
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

// A lock error that is not "someone else holds it" is returned as ErrStore, and
// the lock file is closed.
func TestLockReportsTryLockFailure(t *testing.T) {
	fs := NewFileStore(filepath.Join(t.TempDir(), "seen.json"))
	fs.try = func(*os.File) (bool, error) { return false, errors.New("injected") }
	if _, err := fs.Lock(); !errors.Is(err, ErrStore) {
		t.Fatalf("got %v", err)
	}
}

// The OS lock calls report errors (here: a closed file) instead of claiming the lock.
func TestOSLockCallsReportErrors(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "x"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if ok, err := tryLock(f); ok || err == nil {
		t.Fatalf("tryLock on a closed file: %v, %v", ok, err)
	}
	if err := unlock(f); err == nil {
		t.Fatal("unlock on a closed file succeeded")
	}
}

func TestLockOpenFailure(t *testing.T) {
	fs := NewFileStore(filepath.Join(t.TempDir(), "missing-dir", "seen.json"))
	if _, err := fs.Lock(); !errors.Is(err, ErrStore) {
		t.Fatalf("got %v", err)
	}
}
