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
	if _, err := (FileStore{Dir: filepath.Join(dir, "root.key", "x")}).Exists(); err == nil {
		t.Fatal("want stat error")
	}
	if err := (FileStore{Dir: filepath.Join(dir, "root.key")}).Save(r.Private); err == nil {
		t.Fatal("want mkdir error")
	}
}
