// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
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
	sig, err := sk.Sign(msg, "version=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sk.Sign(msg, "a\nb"); err == nil {
		t.Fatal("multi-line trusted comment accepted")
	}
	if _, err := pk.Verify(msg, append(sig, "extra\n"...)); err == nil {
		t.Fatal("trailing lines accepted")
	}
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

// RFC 7914 section 11 PBKDF2-HMAC-SHA256 vector (c=1 and c=80000 truncated to 32 bytes).
func TestPBKDF2Vector(t *testing.T) {
	got := hex.EncodeToString(pbkdf2([]byte("passwd"), []byte("salt"), 1))
	if got != "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" {
		t.Fatalf("pbkdf2: %s", got)
	}
}

func TestKeyFiles(t *testing.T) {
	sk, pk, _ := GenerateKey()
	pk2, err := ParsePublicKey(pk.Marshal())
	if err != nil || !bytes.Equal(pk2.Key, pk.Key) || pk2.ID != pk.ID {
		t.Fatalf("public round trip: %v", err)
	}
	kdfIterations = 10 // keep the test fast; the stored count is honoured on parse
	enc, err := sk.MarshalEncrypted("pw")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte(base64.StdEncoding.EncodeToString(sk.Seed))) {
		t.Fatal("seed stored in the clear")
	}
	if _, err := ParseSecretKey(enc, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := sk.MarshalEncrypted(""); err == nil {
		t.Fatal("empty password accepted")
	}
	tampered := []byte(strings.Replace(string(enc), "\n", "\nA", 1)) // corrupts the payload
	if _, err := ParseSecretKey(tampered, "pw"); err == nil {
		t.Fatal("tampered key file accepted")
	}
	sk2, err := ParseSecretKey(enc, "pw")
	if err != nil || !bytes.Equal(sk2.Seed, sk.Seed) || sk2.ID != sk.ID {
		t.Fatalf("secret round trip: %v", err)
	}
	for _, s := range []string{"", "x\n", "untrusted comment: x\n!!!\n", "untrusted comment: x\nAAAA\n"} {
		if _, err := ParsePublicKey([]byte(s)); err == nil {
			t.Errorf("public accepted %q", s)
		}
	}
	for _, s := range []string{"", "wrong\nAAAA\n", "parley release secret key\n!!!\n"} {
		if _, err := ParseSecretKey([]byte(s), "pw"); err == nil {
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
	if !strings.Contains(string(a), `"platform"`) || !strings.Contains(string(a), `"go"`) {
		t.Fatalf("toolchain missing from sbom: %s", a)
	}
	if _, err := SBOM("v1", []string{filepath.Join(t.TempDir(), "nope")}); err == nil {
		t.Fatal("missing binary accepted")
	}
}

// TestMinisignInterop checks both directions against the real minisign tool.
// It is skipped when minisign is not installed; CI installs it.
func TestMinisignInterop(t *testing.T) {
	bin, err := exec.LookPath("minisign")
	if err != nil {
		t.Skip("minisign not installed")
	}
	dir := t.TempDir()
	msg := filepath.Join(dir, "msg")
	if err := os.WriteFile(msg, []byte("release bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			t.Fatalf("minisign %v: %v\n%s", args, err, out)
		}
	}

	// Ours -> minisign.
	sk, pk, _ := GenerateKey()
	pub := filepath.Join(dir, "ours.pub")
	os.WriteFile(pub, pk.Marshal(), 0o644)
	sig, err := sk.Sign([]byte("release bytes"), "version=1")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(msg+".minisig", sig, 0o644)
	run("-V", "-p", pub, "-m", msg)

	// minisign (legacy, non-prehashed) -> ours.
	mpub, msec := filepath.Join(dir, "m.pub"), filepath.Join(dir, "m.key")
	run("-G", "-W", "-f", "-p", mpub, "-s", msec)
	run("-S", "-l", "-s", msec, "-m", msg, "-t", "trusted-x", "-x", msg+".m.minisig")
	pubData, _ := os.ReadFile(mpub)
	mpk, err := ParsePublicKey(pubData)
	if err != nil {
		t.Fatal(err)
	}
	sigData, _ := os.ReadFile(msg + ".m.minisig")
	c, err := mpk.Verify([]byte("release bytes"), sigData)
	if err != nil || c != "trusted-x" {
		t.Fatalf("verify minisign signature: %q %v", c, err)
	}
}
