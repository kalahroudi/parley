// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package fsperm

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type fakeTemp struct {
	name                    string
	writeErr, syncErr, clsE error
	closed                  bool
	wrote                   []byte
}

func (f *fakeTemp) Name() string { return f.name }
func (f *fakeTemp) Write(p []byte) (int, error) {
	f.wrote = append(f.wrote, p...)
	return len(p), f.writeErr
}
func (f *fakeTemp) Sync() error  { return f.syncErr }
func (f *fakeTemp) Close() error { f.closed = true; return f.clsE }

func TestWriteAtomicReplacesWholeFilesWithPrivateMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	for _, s := range []string{"one", "two, longer", "3"} {
		if err := WriteAtomic(p, []byte(s)); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(p); string(b) != s {
			t.Errorf("got %q want %q", b, s)
		}
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %o", fi.Mode().Perm())
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "f.tmp*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
	if err := WriteAtomic(filepath.Join(dir, "missing", "f"), nil); err == nil {
		t.Error("a missing directory must fail")
	}
}

func TestWriteAtomicFailsAtEveryStepAndCleansUp(t *testing.T) {
	boom := errors.New("boom")
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	real := func(t *testing.T) *fakeTemp {
		f, err := os.CreateTemp(dir, "f.tmp*")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		return &fakeTemp{name: f.Name()}
	}
	cases := map[string]func(*fakeTemp, *atomicOps){
		"write":  func(f *fakeTemp, _ *atomicOps) { f.writeErr = boom },
		"sync":   func(f *fakeTemp, _ *atomicOps) { f.syncErr = boom },
		"close":  func(f *fakeTemp, _ *atomicOps) { f.clsE = boom },
		"rename": func(_ *fakeTemp, o *atomicOps) { o.rename = func(string, string) error { return boom } },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			f := real(t)
			o := atomicOps{create: func(string, string) (tempFile, error) { return f, nil }, rename: os.Rename, syncDir: func(string) error { return nil }}
			mod(f, &o)
			if err := writeAtomic(p, []byte("new"), o); !errors.Is(err, boom) {
				t.Fatalf("got %v", err)
			}
			if !f.closed {
				t.Error("temp file left open")
			}
			if _, err := os.Stat(f.name); !errors.Is(err, os.ErrNotExist) {
				t.Error("temp file not removed")
			}
			if b, _ := os.ReadFile(p); string(b) != "old" {
				t.Errorf("the old file changed: %q", b)
			}
		})
	}
	o := atomicOps{create: func(string, string) (tempFile, error) { return nil, boom }}
	if err := writeAtomic(p, nil, o); !errors.Is(err, boom) {
		t.Errorf("create: %v", err)
	}
	// A failure to sync the directory is reported (the data is renamed but not known durable).
	o = osAtomic
	o.syncDir = func(string) error { return boom }
	if err := writeAtomic(p, []byte("x"), o); !errors.Is(err, boom) {
		t.Errorf("syncDir: %v", err)
	}
}

func TestSyncDir(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Error(err)
	}
	if runtime.GOOS != "windows" {
		if err := syncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Error("a missing directory must fail")
		}
	}
}
