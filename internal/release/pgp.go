// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha1" //nolint:gosec // OpenPGP v4 key fingerprints are defined as SHA-1; signatures use SHA-256
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// apt can verify nothing but OpenPGP, and the project has one signing key: the Ed25519 key of the release pipeline
// (minisign format). This file writes the OpenPGP encoding of that same key and of signatures made with it, so the
// apt repository is signed by the project key and not by a second one. Only what apt needs is implemented: a v4
// EdDSA public key with one user id, binary and clear-signed signatures with SHA-256. Format: RFC 4880 and the
// GnuPG EdDSA extension (public key algorithm 22, curve OID 1.3.6.1.4.1.11591.15.1).
const (
	pgpAlgEdDSA  = 22
	pgpHashSHA2  = 8
	pgpSigBinary = 0x00
	pgpSigText   = 0x01
	pgpSigCert   = 0x13
	// pgpKeyCreated is the creation time written into the key (2026-01-01 UTC). A minisign key has no creation
	// time, and the fingerprint includes it, so it is a constant: the same key always has the same fingerprint.
	pgpKeyCreated = 1767225600
)

var ed25519OID = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}

// pgpKey is the OpenPGP view of a release key.
type pgpKey struct {
	priv ed25519.PrivateKey
	body []byte // public key packet body
	fp   [20]byte
}

func newPGPKey(s SecretKey) *pgpKey {
	priv := ed25519.NewKeyFromSeed(s.Seed)
	pub := priv.Public().(ed25519.PublicKey)
	body := []byte{4, 0, 0, 0, 0, pgpAlgEdDSA, byte(len(ed25519OID))}
	binary.BigEndian.PutUint32(body[1:5], pgpKeyCreated)
	body = append(body, ed25519OID...)
	body = append(body, mpi(append([]byte{0x40}, pub...))...)
	h := sha1.New() //nolint:gosec // see above
	h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	k := &pgpKey{priv: priv, body: body}
	copy(k.fp[:], h.Sum(nil))
	return k
}

// mpi encodes a big-endian integer as an OpenPGP multiprecision integer: a 2-byte bit count and the bytes without
// leading zeros.
func mpi(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	bits := 0
	if len(b) > 0 {
		bits = (len(b)-1)*8 + bitLen(b[0])
	}
	return append([]byte{byte(bits >> 8), byte(bits)}, b...)
}

func bitLen(b byte) int {
	n := 0
	for ; b != 0; b >>= 1 {
		n++
	}
	return n
}

// packet frames a packet body with a new-format header.
func packet(tag byte, body []byte) []byte {
	out := []byte{0xC0 | tag}
	switch n := len(body); {
	case n < 192:
		out = append(out, byte(n))
	case n < 8384:
		out = append(out, byte((n-192)>>8)+192, byte(n-192))
	default:
		out = append(out, 0xFF, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, body...)
}

// sign makes a v4 signature packet of type sigType over data (already in the form that type hashes), with extra
// hashed subpackets.
func (k *pgpKey) sign(sigType byte, data []byte, extra []byte) []byte {
	creation := make([]byte, 4)
	binary.BigEndian.PutUint32(creation, pgpKeyCreated)
	hashed := append([]byte{5, 2}, creation...) // signature creation time
	hashed = append(hashed, 22, 33, 4)          // issuer fingerprint, version 4
	hashed = append(hashed, k.fp[:]...)
	hashed = append(hashed, extra...)
	header := []byte{4, sigType, pgpAlgEdDSA, pgpHashSHA2, byte(len(hashed) >> 8), byte(len(hashed))}
	header = append(header, hashed...)
	h := sha256.New()
	h.Write(data)
	h.Write(header)
	h.Write([]byte{4, 0xFF, 0, 0, byte(len(header) >> 8), byte(len(header))})
	digest := h.Sum(nil)
	sig := ed25519.Sign(k.priv, digest) // OpenPGP EdDSA signs the hash digest
	body := append([]byte(nil), header...)
	body = append(body, 0, 10, 9, 16) // unhashed: issuer key id, 8 bytes
	body = append(body, k.fp[12:]...)
	body = append(body, digest[:2]...)
	body = append(body, mpi(sig[:32])...)
	body = append(body, mpi(sig[32:])...)
	return packet(2, body)
}

func (k *pgpKey) keyPacket() []byte { return packet(6, k.body) }

func (k *pgpKey) userID() string { return "Parley release key" }

// PublicKeyBlock returns the armored OpenPGP public key (key, user id, self-signature) of the release key and its
// fingerprint in hex. The self-signature is what lets gpg accept the key.
func PublicKeyBlock(s SecretKey) (armored []byte, fingerprint string) {
	k := newPGPKey(s)
	uid := []byte(k.userID())
	certData := append([]byte{0x99, byte(len(k.body) >> 8), byte(len(k.body))}, k.body...)
	certData = append(certData, 0xB4, 0, 0, 0, byte(len(uid)))
	certData = append(certData, uid...)
	cert := k.sign(pgpSigCert, certData, []byte{2, 27, 0x03}) // key flags: certify and sign
	block := append(k.keyPacket(), packet(13, uid)...)
	block = append(block, cert...)
	return armor("PUBLIC KEY BLOCK", block), fmt.Sprintf("%X", k.fp)
}

// SignRelease signs an apt Release file with the release key and returns the detached signature (Release.gpg) and
// the clear-signed file (InRelease), both for apt to verify against PublicKeyBlock.
func SignRelease(s SecretKey, releaseFile []byte) (detached, inRelease []byte) {
	k := newPGPKey(s)
	detached = armor("SIGNATURE", k.sign(pgpSigBinary, releaseFile, nil))
	text := canonicalText(releaseFile)
	sig := armor("SIGNATURE", k.sign(pgpSigText, text, nil))
	var b bytes.Buffer
	b.WriteString("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n")
	for _, line := range strings.Split(strings.TrimSuffix(string(releaseFile), "\n"), "\n") {
		if strings.HasPrefix(line, "-") {
			line = "- " + line // dash escaping
		}
		b.WriteString(line + "\n")
	}
	b.Write(sig)
	return detached, b.Bytes()
}

// canonicalText is the text a clear signature covers: lines without trailing spaces or tabs, joined by CRLF, with
// no line ending after the last line.
func canonicalText(b []byte) []byte {
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t\r")
	}
	return []byte(strings.Join(lines, "\r\n"))
}

// armor wraps packets in ASCII armor with a CRC-24.
func armor(kind string, data []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "-----BEGIN PGP %s-----\n\n", kind)
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 64 {
		b.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	b.WriteString(enc + "\n")
	crc := crc24(data)
	b.WriteString("=" + base64.StdEncoding.EncodeToString([]byte{byte(crc >> 16), byte(crc >> 8), byte(crc)}) + "\n")
	fmt.Fprintf(&b, "-----END PGP %s-----\n", kind)
	return b.Bytes()
}

func crc24(data []byte) uint32 {
	crc := uint32(0xB704CE)
	for _, c := range data {
		crc ^= uint32(c) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= 0x1864CFB
			}
		}
	}
	return crc & 0xFFFFFF
}
