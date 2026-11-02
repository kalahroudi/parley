// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeygenSignVerifyAndNoOverwrite(t *testing.T) {
	d := t.TempDir()
	if err := run([]string{"keygen", filepath.Join(d, "n"), filepath.Join(d, "n.pub")}); err == nil {
		t.Fatal("keygen without a password accepted")
	}
	t.Setenv(passwordEnv, "test-password")
	sk, pk := filepath.Join(d, "k"), filepath.Join(d, "k.pub")
	if err := run([]string{"keygen", sk, pk}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", sk, filepath.Join(d, "x.pub")}); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	f := filepath.Join(d, "f")
	os.WriteFile(f, []byte("data"), 0o644)
	if err := run([]string{"sign", sk, f, "c"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", pk, f}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", sk, f, "a\nb"}); err == nil {
		t.Fatal("multi-line comment accepted")
	}
	if err := run([]string{"bogus"}); err == nil {
		t.Fatal("unknown command accepted")
	}
}

func TestChecksumsSBOMAndVerifyChecksums(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "a"), []byte("A"), 0o644)
	sums := filepath.Join(d, "SHA256SUMS")
	if err := run([]string{"checksums", d, sums, "a"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify-checksums", sums}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "a"), []byte("changed"), 0o644)
	if err := run([]string{"verify-checksums", sums}); err == nil {
		t.Fatal("modified file accepted")
	}
	if err := run([]string{"verify-checksums", filepath.Join(d, "none")}); err == nil {
		t.Fatal("missing sums file accepted")
	}
	if err := run([]string{"checksums", d, sums, "missing"}); err == nil {
		t.Fatal("missing file accepted")
	}

	// The SBOM describes this very test binary, which is a Go binary.
	bom := filepath.Join(d, "sbom.json")
	if err := run([]string{"sbom", "v1", bom, os.Args[0]}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(bom); err != nil || !strings.Contains(string(data), "CycloneDX") {
		t.Fatalf("sbom: %v %q", err, data)
	}
	if err := run([]string{"sbom", "v1", bom, filepath.Join(d, "a")}); err == nil {
		t.Fatal("non-Go file accepted")
	}
}

func TestRunRejectsBadUsageAndInputs(t *testing.T) {
	d := t.TempDir()
	t.Setenv(passwordEnv, "test-password")
	sk, pk := filepath.Join(d, "k"), filepath.Join(d, "k.pub")
	if err := run([]string{"keygen", sk, pk}); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(d, "f")
	os.WriteFile(f, []byte("data"), 0o644)
	none := filepath.Join(d, "none")
	for name, args := range map[string][]string{
		"no args":                  nil,
		"keygen arity":             {"keygen", sk},
		"keygen into a bad dir":    {"keygen", filepath.Join(d, "x", "k"), filepath.Join(d, "x", "k.pub")},
		"keygen public file taken": {"keygen", filepath.Join(d, "k2"), pk},
		"sign with no key file":    {"sign", none, f, "c"},
		"sign a missing file":      {"sign", sk, none, "c"},
		"sign with a bad key file": {"sign", f, f, "c"},
		"verify no public key":     {"verify", none, f},
		"verify bad public key":    {"verify", f, f},
		"verify missing file":      {"verify", pk, none},
		"verify missing signature": {"verify", pk, f},
		"verify arity":             {"verify", pk},
	} {
		if err := run(args); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The failed keygen over an existing public key must not leave its secret key behind.
	if _, err := os.Stat(filepath.Join(d, "k2")); err == nil {
		t.Error("secret key left behind after the public key could not be written")
	}
	// Sign without a password.
	t.Setenv(passwordEnv, "")
	if err := run([]string{"sign", sk, f, "c"}); err == nil {
		t.Error("sign without a password accepted")
	}
}

func TestCreateFileNeverOverwritesAndCleansUp(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "x")
	if err := createFile(p, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createFile(p, []byte("2"), 0o600); err == nil {
		t.Fatal("overwrote an existing file")
	}
	if data, _ := os.ReadFile(p); string(data) != "1" {
		t.Fatalf("content %q", data)
	}
}
