// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package root

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewAndRecover(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if r.Fingerprint != Fingerprint(r.Public) || !strings.Contains(r.Fingerprint, "-") {
		t.Fatalf("bad fingerprint %q", r.Fingerprint)
	}
	if strings.Contains(string(r.Backup), string(r.Private.Seed())) {
		t.Fatal("backup holds the seed in clear")
	}
	if r.String() != "root("+r.Fingerprint+")" {
		t.Fatal(r.String())
	}
	for _, code := range []string{r.RecoveryCode, strings.ToLower(strings.ReplaceAll(r.RecoveryCode, "-", " "))} {
		priv, err := Recover(code, r.Backup)
		if err != nil {
			t.Fatal(err)
		}
		if !priv.Equal(r.Private) {
			t.Fatal("recovered key differs")
		}
	}
	msg := []byte("m")
	priv, _ := Recover(r.RecoveryCode, r.Backup)
	if !ed25519.Verify(r.Public, msg, ed25519.Sign(priv, msg)) {
		t.Fatal("signature does not verify")
	}
}

func TestRecoverRejects(t *testing.T) {
	r, _ := New()
	other, _ := New()
	var b backupFile
	_ = json.Unmarshal(r.Backup, &b)
	mut := func(f func(*backupFile)) []byte {
		c := b
		c.Ciphertext = append([]byte(nil), b.Ciphertext...)
		f(&c)
		out, _ := json.Marshal(c)
		return out
	}
	cases := map[string]struct {
		code   string
		backup []byte
	}{
		"wrong code":  {other.RecoveryCode, r.Backup},
		"not json":    {r.RecoveryCode, []byte("x")},
		"version":     {r.RecoveryCode, mut(func(c *backupFile) { c.Version = 9 })},
		"rounds":      {r.RecoveryCode, mut(func(c *backupFile) { c.Rounds = 1 })},
		"nonce":       {r.RecoveryCode, mut(func(c *backupFile) { c.Nonce = c.Nonce[:3] })},
		"tampered":    {r.RecoveryCode, mut(func(c *backupFile) { c.Ciphertext[0] ^= 1 })},
		"swapped pub": {r.RecoveryCode, mut(func(c *backupFile) { c.Public = other.Public })},
		"short seed":  {r.RecoveryCode, mut(func(c *backupFile) { c.Ciphertext = c.Ciphertext[:20] })},
	}
	for name, c := range cases {
		if _, err := Recover(c.code, c.backup); !errors.Is(err, ErrBadRecovery) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestPublicMismatchAfterReseal(t *testing.T) {
	// A backup whose sealed seed does not match the declared public key.
	r, _ := New()
	other, _ := New()
	bad, err := seal(r.RecoveryCode, other.Private.Seed(), r.Public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(r.RecoveryCode, bad); !errors.Is(err, ErrBadRecovery) {
		t.Fatal(err)
	}
}

func TestFileStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "p")
	s := FileStore{Dir: dir}
	if ok, err := s.Exists(); ok || err != nil {
		t.Fatal(ok, err)
	}
	r, _ := New()
	if err := s.Save(r.Private); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Exists(); !ok {
		t.Fatal("should exist")
	}
	if err := s.Save(r.Private); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "root.key")); fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("mode %v", fi.Mode())
	}
	// A NUL in the path is a stat error on every OS. (A path through a regular
	// file is ENOTDIR on Unix but "not found" on Windows, so it can't be used.)
	if _, err := (FileStore{Dir: "bad\x00dir"}).Exists(); err == nil {
		t.Fatal("want stat error")
	}
	if err := (FileStore{Dir: filepath.Join(dir, "root.key")}).Save(r.Private); err == nil {
		t.Fatal("want mkdir error")
	}
}

func TestFileStoreSaveFailureLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	r, _ := New()
	old := syncFile
	syncFile = func(*os.File) error { return errors.New("disk full") }
	err := FileStore{Dir: dir}.Save(r.Private)
	syncFile = old
	if err == nil {
		t.Fatal("want error")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("leftovers: %v", ents)
	}
	// An existing key is untouched and no temp file remains.
	s := FileStore{Dir: dir}
	if err := s.Save(r.Private); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(r.Private); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("leftovers: %v", ents)
	}
}

// Each step of Save can fail (create, write, close, link); none leaves a file behind.
func TestFileStoreSaveFailsAtEveryStep(t *testing.T) {
	r, _ := New()
	steps := map[string]func() func(){
		"create": func() func() {
			old := createTemp
			createTemp = func(string, string) (*os.File, error) { return nil, errors.New("injected") }
			return func() { createTemp = old }
		},
		"write": func() func() { // a closed temp file cannot be written
			old := createTemp
			createTemp = func(d, p string) (*os.File, error) {
				f, err := os.CreateTemp(d, p)
				f.Close()
				return f, err
			}
			return func() { createTemp = old }
		},
		"close": func() func() { // closed during sync, so the final close fails
			old := syncFile
			syncFile = func(f *os.File) error { f.Close(); return nil }
			return func() { syncFile = old }
		},
		"link": func() func() {
			old := link
			link = func(string, string) error { return errors.New("injected") }
			return func() { link = old }
		},
	}
	for name, inject := range steps {
		dir := t.TempDir()
		restore := inject()
		err := FileStore{Dir: dir}.Save(r.Private)
		restore()
		if err == nil || errors.Is(err, ErrExists) {
			t.Errorf("%s: got %v", name, err)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Errorf("%s: leftovers: %v", name, ents)
		}
	}
}

func TestFileStoreLoad(t *testing.T) {
	s := FileStore{Dir: t.TempDir()}
	if _, err := s.Load(); !errors.Is(err, ErrNoRoot) {
		t.Fatalf("empty store: %v", err)
	}
	r, _ := New()
	if err := s.Save(r.Private); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil || !got.Equal(r.Private) {
		t.Fatalf("load: %v", err)
	}
	os.WriteFile(filepath.Join(s.Dir, "root.key"), []byte("short"), 0o600)
	if _, err := s.Load(); err == nil {
		t.Fatal("short key accepted")
	}
	os.Remove(filepath.Join(s.Dir, "root.key"))
	os.Mkdir(filepath.Join(s.Dir, "root.key"), 0o700) // unreadable as a file
	if _, err := s.Load(); err == nil || errors.Is(err, ErrNoRoot) {
		t.Fatalf("read error: %v", err)
	}
}
