// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignVerify(t *testing.T) {
	sk, pk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if got := sk.Public(); !bytes.Equal(got.Key, pk.Key) || got.ID != pk.ID {
		t.Fatal("Public mismatch")
	}
	msg := []byte("hello")
	sig := sk.Sign(msg, "version=1")
	c, err := pk.Verify(msg, sig)
	if err != nil || c != "version=1" {
		t.Fatalf("verify: %q %v", c, err)
	}
	if _, err := pk.Verify([]byte("tampered"), sig); err == nil {
		t.Fatal("tampered message accepted")
	}
	forged := strings.Replace(string(sig), "version=1", "version=2", 1)
	if _, err := pk.Verify(msg, []byte(forged)); err == nil {
		t.Fatal("tampered trusted comment accepted")
	}
	_, other, _ := GenerateKey()
	if _, err := other.Verify(msg, sig); err == nil {
		t.Fatal("wrong key accepted")
	}
	// Same key id but different key: signature itself must fail.
	other.ID = pk.ID
	if _, err := other.Verify(msg, sig); err == nil {
		t.Fatal("wrong key with same id accepted")
	}
}

func TestVerifyMalformed(t *testing.T) {
	_, pk, _ := GenerateKey()
	for _, s := range []string{"", "a\nb\n", "a\n!!!\ntrusted comment: x\n!!!\n", "a\nRWQ=\ntrusted comment: x\nAA==\n"} {
		if _, err := pk.Verify([]byte("m"), []byte(s)); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestKeyFiles(t *testing.T) {
	sk, pk, _ := GenerateKey()
	pk2, err := ParsePublicKey(pk.Marshal())
	if err != nil || !bytes.Equal(pk2.Key, pk.Key) || pk2.ID != pk.ID {
		t.Fatalf("public round trip: %v", err)
	}
	sk2, err := ParseSecretKey(sk.Marshal())
	if err != nil || !bytes.Equal(sk2.Seed, sk.Seed) || sk2.ID != sk.ID {
		t.Fatalf("secret round trip: %v", err)
	}
	for _, s := range []string{"", "x\n", "untrusted comment: x\n!!!\n", "untrusted comment: x\nAAAA\n"} {
		if _, err := ParsePublicKey([]byte(s)); err == nil {
			t.Errorf("public accepted %q", s)
		}
	}
	for _, s := range []string{"", "wrong\nAAAA\n", "parley release secret key\n!!!\n"} {
		if _, err := ParseSecretKey([]byte(s)); err == nil {
			t.Errorf("secret accepted %q", s)
		}
	}
	// Wrong algorithm byte.
	bad := strings.Replace(string(pk.Marshal()), "\n", "\nAAAA", 1)
	if _, err := ParsePublicKey([]byte(bad)); err == nil {
		t.Error("bad public accepted")
	}
}

func TestChecksums(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "b"), []byte("B"), 0o644)
	os.WriteFile(filepath.Join(dir, "a"), []byte("A"), 0o644)
	sums, err := Checksums(dir, []string{"b", "a"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(strings.Split(string(sums), "\n")[0], "  a") {
		t.Fatalf("not sorted: %s", sums)
	}
	if err := VerifyChecksums(dir, sums); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "a"), []byte("changed"), 0o644)
	if err := VerifyChecksums(dir, sums); err == nil {
		t.Fatal("modified file accepted")
	}
	if _, err := Checksums(dir, []string{"missing"}); err == nil {
		t.Fatal("missing file accepted")
	}
	for _, s := range []string{"", "zz  a\n", strings.Repeat("0", 64) + "  ../a\n", strings.Repeat("0", 64) + "  nofile\n"} {
		if VerifyChecksums(dir, []byte(s)) == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestSBOM(t *testing.T) {
	exe, err := os.Executable() // the running test binary is a Go binary with build info
	if err != nil {
		t.Fatal(err)
	}
	a, err := SBOM("v1.2.3", []string{exe})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SBOM("v1.2.3", []string{exe})
	if !bytes.Equal(a, b) {
		t.Fatal("SBOM not deterministic")
	}
	var doc struct {
		BOMFormat  string
		Components []struct{ Type, Name, Version string }
	}
	if err := json.Unmarshal(a, &doc); err != nil || doc.BOMFormat != "CycloneDX" || len(doc.Components) == 0 {
		t.Fatalf("bad sbom: %v %s", err, a)
	}
	if _, err := SBOM("v1", []string{filepath.Join(t.TempDir(), "nope")}); err == nil {
		t.Fatal("missing binary accepted")
	}
}
