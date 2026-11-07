// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha1" //nolint:gosec // see pgp.go
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// unarmor reads one armored block and checks its CRC-24.
func unarmor(t *testing.T, b []byte, kind string) []byte {
	t.Helper()
	s := string(b)
	begin, end := "-----BEGIN PGP "+kind+"-----\n\n", "\n-----END PGP "+kind+"-----\n"
	i := strings.Index(s, begin)
	if i < 0 || !strings.HasSuffix(s, end) {
		t.Fatalf("not an armored %s:\n%s", kind, s)
	}
	body := strings.TrimSuffix(s[i+len(begin):], end)
	j := strings.LastIndex(body, "\n=")
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body[:j], "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	crc, err := base64.StdEncoding.DecodeString(body[j+2:])
	if err != nil || len(crc) != 3 || uint32(crc[0])<<16|uint32(crc[1])<<8|uint32(crc[2]) != crc24(data) {
		t.Fatalf("bad CRC-24 (%v)", err)
	}
	for _, line := range strings.Split(body[:j], "\n") {
		if len(line) > 64 {
			t.Fatalf("armor line of %d characters", len(line))
		}
	}
	return data
}

// readPacket splits one packet (new-format header) off the front of b.
func readPacket(t *testing.T, b []byte) (tag byte, body, rest []byte) {
	t.Helper()
	if b[0]&0xC0 != 0xC0 {
		t.Fatalf("not a new-format packet header: %#x", b[0])
	}
	tag, n, off := b[0]&0x3F, 0, 2
	switch {
	case b[1] < 192:
		n = int(b[1])
	case b[1] < 224:
		n, off = (int(b[1])-192)<<8+int(b[2])+192, 3
	case b[1] == 255:
		n, off = int(binary.BigEndian.Uint32(b[2:6])), 6
	default:
		t.Fatal("partial length")
	}
	return tag, b[off : off+n], b[off+n:]
}

// verifySig checks a v4 EdDSA/SHA-256 signature packet over data for the public key body, independently of the
// code that made it: it re-derives the hashed trailer from the packet itself.
func verifySig(t *testing.T, sigPacket, data []byte, keyBody []byte, wantType byte) {
	t.Helper()
	tag, p, rest := readPacket(t, sigPacket)
	if tag != 2 || len(rest) != 0 || p[0] != 4 || p[1] != wantType || p[2] != pgpAlgEdDSA || p[3] != pgpHashSHA2 {
		t.Fatalf("signature header % x", p[:4])
	}
	hl := int(p[4])<<8 | int(p[5])
	hashed := p[6 : 6+hl]
	ul := int(p[6+hl])<<8 | int(p[7+hl])
	tail := p[8+hl+ul:]
	h := sha256.New()
	h.Write(data)
	h.Write(p[:6+hl])
	h.Write([]byte{4, 0xFF, 0, 0, byte((6 + hl) >> 8), byte(6 + hl)})
	digest := h.Sum(nil)
	if !bytes.Equal(tail[:2], digest[:2]) {
		t.Fatal("left 16 bits of the hash differ")
	}
	mpiBytes := func(b []byte) ([]byte, []byte) {
		bits := int(b[0])<<8 | int(b[1])
		n := (bits + 7) / 8
		v := b[2 : 2+n]
		if n > 0 && (v[0] == 0 || bitLen(v[0]) != bits-(n-1)*8) {
			t.Fatal("MPI is not minimal")
		}
		return v, b[2+n:]
	}
	r, tail2 := mpiBytes(tail[2:])
	s, tail3 := mpiBytes(tail2)
	if len(tail3) != 0 {
		t.Fatal("trailing bytes in signature")
	}
	sig := append(append(make([]byte, 32-len(r)), r...), append(make([]byte, 32-len(s)), s...)...)
	// The public point is the last MPI of the key body: 0x40 followed by the 32 byte key.
	pt := keyBody[len(keyBody)-33:]
	if !ed25519.Verify(ed25519.PublicKey(pt[1:]), digest, sig) {
		t.Fatal("EdDSA signature does not verify")
	}
	// The hashed area names the issuer as this key's fingerprint.
	fp := newPGPKeyFromBody(keyBody)
	if !bytes.Contains(hashed, append([]byte{22, 33, 4}, fp[:]...)) {
		t.Fatal("issuer fingerprint missing from the hashed area")
	}
}

func newPGPKeyFromBody(body []byte) (fp [20]byte) {
	k := &pgpKey{body: body}
	h := sha1sum(append([]byte{0x99, byte(len(k.body) >> 8), byte(len(k.body))}, k.body...))
	copy(fp[:], h)
	return fp
}

func testKey(t *testing.T) SecretKey {
	t.Helper()
	sk, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

func TestPublicKeyBlockStructure(t *testing.T) {
	sk := testKey(t)
	block, fp := PublicKeyBlock(sk)
	again, fp2 := PublicKeyBlock(sk)
	if !bytes.Equal(block, again) || fp != fp2 || len(fp) != 40 {
		t.Fatal("not deterministic")
	}
	data := unarmor(t, block, "PUBLIC KEY BLOCK")
	tag, key, rest := readPacket(t, data)
	if tag != 6 || key[0] != 4 || key[5] != pgpAlgEdDSA || !bytes.Equal(key[6:16], append([]byte{9}, ed25519OID...)) {
		t.Fatalf("key packet % x", key)
	}
	if binary.BigEndian.Uint32(key[1:5]) != pgpKeyCreated || !bytes.Equal(key[16:19], []byte{0x01, 0x07, 0x40}) || len(key) != 16+2+33 {
		t.Fatalf("key packet fields % x", key)
	}
	if !bytes.Equal(key[19:], sk.Public().Key) {
		t.Fatal("public point differs from the release key")
	}
	tag, uid, rest := readPacket(t, rest)
	if tag != 13 || string(uid) != "Parley release key" {
		t.Fatalf("user id %q", uid)
	}
	certData := append([]byte{0x99, 0, byte(len(key))}, key...)
	certData = append(certData, 0xB4, 0, 0, 0, byte(len(uid)))
	certData = append(certData, uid...)
	verifySig(t, rest, certData, key, pgpSigCert)
	if strings.ToUpper(fp) != fp || !strings.HasSuffix(fp, strings.ToUpper(newKeyIDHex(key))) {
		t.Fatalf("fingerprint %s", fp)
	}
	// A different key has a different fingerprint; the same minisign key id does not matter.
	if _, other := PublicKeyBlock(testKey(t)); other == fp {
		t.Fatal("two keys, one fingerprint")
	}
}

func newKeyIDHex(body []byte) string {
	fp := newPGPKeyFromBody(body)
	return strings.ToUpper(hexOf(fp[12:]))
}

func TestSignReleaseVerifiesAndDetectsChange(t *testing.T) {
	sk := testKey(t)
	rel := []byte("Origin: Parley\nSHA256:\n abc 12 Packages\n-dashed line\ntrailing  \n")
	detached, inRelease := SignRelease(sk, rel)
	block, _ := PublicKeyBlock(sk)
	_, key, _ := readPacket(t, unarmor(t, block, "PUBLIC KEY BLOCK"))

	verifySig(t, unarmor(t, detached, "SIGNATURE"), rel, key, pgpSigBinary)

	s := string(inRelease)
	if !strings.HasPrefix(s, "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Parley\n") || !strings.Contains(s, "\n- -dashed line\n") {
		t.Fatalf("clear-signed header or dash escaping:\n%s", s)
	}
	sigAt := strings.Index(s, "-----BEGIN PGP SIGNATURE-----")
	verifySig(t, unarmor(t, []byte(s[sigAt:]), "SIGNATURE"), canonicalText(rel), key, pgpSigText)

	// The text is hashed in canonical form: trailing spaces and tabs are not signed, line endings are CRLF, and the
	// last line has no ending.
	if !bytes.Equal(canonicalText([]byte("a  \nb\n")), canonicalText([]byte("a\nb\n"))) {
		t.Fatal("trailing spaces are part of the signed text")
	}
	if string(canonicalText([]byte("a\r\nb\n"))) != "a\r\nb" || string(canonicalText([]byte("x"))) != "x" {
		t.Fatalf("canonical text: %q", canonicalText([]byte("a\r\nb\n")))
	}
}

func TestMPIAndPacketLengths(t *testing.T) {
	for in, want := range map[string][]byte{
		"":       {0, 0},
		"00":     {0, 0},
		"01":     {0, 1, 1},
		"7f":     {0, 7, 0x7f},
		"80":     {0, 8, 0x80},
		"0001":   {0, 1, 1},
		"0100":   {0, 9, 1, 0},
		"ff00ff": {0, 24, 0xff, 0, 0xff},
	} {
		raw := make([]byte, len(in)/2)
		for i := range raw {
			raw[i] = hexNibble(in[2*i])<<4 | hexNibble(in[2*i+1])
		}
		if got := mpi(raw); !bytes.Equal(got, want) {
			t.Errorf("mpi(%s) = % x, want % x", in, got, want)
		}
	}
	for _, n := range []int{0, 1, 191, 192, 193, 8383, 8384, 70000} {
		p := packet(2, make([]byte, n))
		tag, body, rest := readPacket(t, p)
		if tag != 2 || len(body) != n || len(rest) != 0 {
			t.Errorf("length %d: tag %d len %d rest %d", n, tag, len(body), len(rest))
		}
	}
}

func TestCRC24Vector(t *testing.T) {
	// "The quick brown fox" is not a standard vector; the empty input is: the initial value.
	if crc24(nil) != 0xB704CE {
		t.Fatalf("crc24(empty) = %#x", crc24(nil))
	}
	// Two inputs of different content differ, and the result is 24 bits.
	if a, b := crc24([]byte("a")), crc24([]byte("b")); a == b || a > 0xFFFFFF || b > 0xFFFFFF {
		t.Fatal("crc24")
	}
}

// Real GnuPG accepts the key and both signatures, and rejects a changed Release. Where gpg is installed it runs
// (always on Linux CI, which fails if gpg is missing; the portable checks above cover the encoding everywhere).
func TestGnuPGAcceptsTheKeyAndSignatures(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		if os.Getenv("CI") != "" && runtime.GOOS == "linux" {
			t.Fatal("gpg is required on Linux CI to check the apt signatures")
		}
		t.Log("gpg not installed: the OpenPGP encoding was checked by the portable tests only")
		return
	}
	sk := testKey(t)
	block, fp := PublicKeyBlock(sk)
	rel := []byte("Origin: Parley\nDate: Sat, 07 Nov 2026 12:30:00 UTC\nSHA256:\n abc 12 Packages\n")
	detached, inRelease := SignRelease(sk, rel)

	home, err := os.MkdirTemp(shortTempBase(), "gh")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	os.Chmod(home, 0o700)
	write := func(name string, b []byte) string {
		p := filepath.Join(home, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command(gpg, append([]string{"--homedir", home, "--batch", "--no-tty", "--status-fd", "1"}, args...)...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run("--import", write("key.asc", block)); err != nil {
		t.Fatalf("import: %v\n%s", err, out)
	}
	out, err := run("--list-keys", "--with-colons", "--with-fingerprint")
	if err != nil || !strings.Contains(strings.ToUpper(out), fp) {
		t.Fatalf("fingerprint %s not listed: %v\n%s", fp, err, out)
	}
	relPath := write("Release", rel)
	good := func(out string, err error) bool {
		return err == nil && strings.Contains(out, "GOODSIG") && strings.Contains(out, fp)
	}
	if out, err := run("--verify", write("Release.gpg", detached), relPath); !good(out, err) {
		t.Fatalf("detached: %v\n%s", err, out)
	}
	if out, err := run("--verify", write("InRelease", inRelease)); !good(out, err) {
		t.Fatalf("clear-signed: %v\n%s", err, out)
	}
	// What apt runs: gpgv against an exported keyring.
	if gpgv, err := exec.LookPath("gpgv"); err == nil {
		ring := filepath.Join(home, "ring.gpg")
		exp, err := exec.Command(gpg, "--homedir", home, "--batch", "--export").Output()
		if err != nil || os.WriteFile(ring, exp, 0o600) != nil {
			t.Fatal("export", err)
		}
		if out, err := exec.Command(gpgv, "--keyring", ring, filepath.Join(home, "InRelease")).CombinedOutput(); err != nil {
			t.Fatalf("gpgv InRelease: %v\n%s", err, out)
		}
		if out, err := exec.Command(gpgv, "--keyring", ring, filepath.Join(home, "Release.gpg"), relPath).CombinedOutput(); err != nil {
			t.Fatalf("gpgv Release.gpg: %v\n%s", err, out)
		}
	}
	// A changed Release and a changed clear-signed body are refused.
	tampered := write("Release", append([]byte("X"), rel[1:]...))
	if out, err := run("--verify", filepath.Join(home, "Release.gpg"), tampered); good(out, err) {
		t.Fatalf("tampered Release accepted:\n%s", out)
	}
	bad := bytes.Replace(inRelease, []byte("abc 12"), []byte("abd 12"), 1)
	if out, err := run("--verify", write("InRelease", bad)); good(out, err) {
		t.Fatalf("tampered InRelease accepted:\n%s", out)
	}
	// Another key's signature is not accepted by the imported key.
	otherSig, _ := SignRelease(testKey(t), rel)
	if out, err := run("--verify", write("Other.gpg", otherSig), relPath); good(out, err) {
		t.Fatalf("a different key's signature accepted:\n%s", out)
	}
}

func shortTempBase() string {
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat("/tmp"); err == nil && fi.IsDir() {
			return "/tmp" // gpg puts sockets in its home directory, and unix socket paths are short
		}
	}
	return ""
}

func hexNibble(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

func sha1sum(b []byte) []byte { h := sha1.New(); h.Write(b); return h.Sum(nil) }
