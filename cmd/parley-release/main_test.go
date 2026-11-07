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

func TestPackagingCommands(t *testing.T) {
	d := t.TempDir()
	for _, goos := range []string{"darwin", "linux"} {
		for _, arch := range []string{"amd64", "arm64"} {
			for _, cmd := range []string{"parleyd", "parley-cli"} {
				os.WriteFile(filepath.Join(d, cmd+"_v1.0.0_"+goos+"_"+arch), []byte(cmd), 0o755)
			}
		}
	}
	out := t.TempDir()
	formula := filepath.Join(out, "parley.rb")
	if err := run([]string{"formula", "v1.0.0", d, formula}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(formula); !strings.Contains(string(b), `version "1.0.0"`) {
		t.Fatal("formula")
	}
	if err := run([]string{"formula", "1.0.0", d, formula}); err == nil {
		t.Fatal("bad tag accepted")
	}
	deb := filepath.Join(out, "parley_1.0.0_amd64.deb")
	if err := run([]string{"deb", "v1.0.0", "amd64", d, deb}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(deb); !strings.HasPrefix(string(b), "!<arch>\n") {
		t.Fatal("deb")
	}
	if err := run([]string{"deb", "v1.0.0", "s390x", d, filepath.Join(out, "x.deb")}); err == nil {
		t.Fatal("bad arch accepted")
	}
	bad := filepath.Join(out, "no", "such", "dir")
	if err := run([]string{"deb", "v1.0.0", "amd64", d, bad}); err == nil {
		t.Fatal("unwritable output accepted")
	}
	if err := run([]string{"formula", "v1.0.0", d, bad}); err == nil {
		t.Fatal("unwritable output accepted")
	}
}

func TestAptCommands(t *testing.T) {
	d := t.TempDir()
	for _, arch := range []string{"amd64", "arm64"} {
		os.WriteFile(filepath.Join(d, "parley_1.0.0_"+arch+".deb"), []byte("deb "+arch), 0o644)
	}
	if err := run([]string{"apt", d, "1800000000"}); err != nil {
		t.Fatal(err)
	}
	rel, _ := os.ReadFile(filepath.Join(d, "Release"))
	if !strings.Contains(string(rel), "Architectures: amd64 arm64") || !strings.Contains(string(rel), "Date: Fri, 15 Jan 2027 08:00:00 UTC") {
		t.Fatalf("Release: %s", rel)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "Packages")); strings.Count(string(b), "Filename: ./parley_1.0.0_") != 2 {
		t.Fatalf("Packages: %s", b)
	}
	for _, bad := range []string{"yesterday", "-5", ""} {
		if err := run([]string{"apt", d, bad}); err == nil {
			t.Errorf("time %q accepted", bad)
		}
	}
	if err := run([]string{"apt", t.TempDir(), "1"}); err == nil {
		t.Fatal("empty repository accepted")
	}
	ro := t.TempDir()
	os.WriteFile(filepath.Join(ro, "parley_1.0.0_amd64.deb"), []byte("x"), 0o644)
	os.Mkdir(filepath.Join(ro, "Packages"), 0o755)
	if err := run([]string{"apt", ro, "1"}); err == nil {
		t.Fatal("unwritable Packages accepted")
	}
	os.Remove(filepath.Join(ro, "Packages"))
	os.Mkdir(filepath.Join(ro, "Release"), 0o755)
	if err := run([]string{"apt", ro, "1"}); err == nil {
		t.Fatal("unwritable Release accepted")
	}

	// Key and signatures need the release key and its password.
	sk, pk := filepath.Join(d, "k"), filepath.Join(d, "k.pub")
	if err := run([]string{"apt-sign", sk, d}); err == nil {
		t.Fatal("signing without a password accepted")
	}
	t.Setenv(passwordEnv, "test-password")
	if err := run([]string{"keygen", sk, pk}); err != nil {
		t.Fatal(err)
	}
	asc := filepath.Join(d, "parley.asc")
	if err := run([]string{"apt-key", sk, asc}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(asc); !strings.HasPrefix(string(b), "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Fatalf("key: %s", b)
	}
	if err := run([]string{"apt-sign", sk, d}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "InRelease")); !strings.HasPrefix(string(b), "-----BEGIN PGP SIGNED MESSAGE-----") {
		t.Fatalf("InRelease: %s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(d, "Release.gpg")); !strings.HasPrefix(string(b), "-----BEGIN PGP SIGNATURE-----") {
		t.Fatalf("Release.gpg: %s", b)
	}
	t.Setenv(passwordEnv, "wrong")
	if err := run([]string{"apt-sign", sk, d}); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err := run([]string{"apt-key", sk, asc}); err == nil {
		t.Fatal("wrong password accepted")
	}
	t.Setenv(passwordEnv, "test-password")
	if err := run([]string{"apt-sign", sk, t.TempDir()}); err == nil {
		t.Fatal("missing Release accepted")
	}
	if err := run([]string{"apt-sign", filepath.Join(d, "none"), d}); err == nil {
		t.Fatal("missing key accepted")
	}
	if err := run([]string{"apt-key", sk, filepath.Join(d, "no", "such", "k.asc")}); err == nil {
		t.Fatal("unwritable output accepted")
	}
	rw := t.TempDir()
	os.WriteFile(filepath.Join(rw, "Release"), []byte("Origin: x\n"), 0o644)
	os.Mkdir(filepath.Join(rw, "Release.gpg"), 0o755)
	if err := run([]string{"apt-sign", sk, rw}); err == nil {
		t.Fatal("unwritable Release.gpg accepted")
	}
	os.Remove(filepath.Join(rw, "Release.gpg"))
	os.Mkdir(filepath.Join(rw, "InRelease"), 0o755)
	if err := run([]string{"apt-sign", sk, rw}); err == nil {
		t.Fatal("unwritable InRelease accepted")
	}
}
