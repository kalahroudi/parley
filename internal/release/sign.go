// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package release implements the project's own-key release pipeline:
// minisign-compatible Ed25519 signing, SHA256SUMS files and a CycloneDX SBOM.
// It uses only the standard library and no vendor signing service.
package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Only the legacy "Ed" minisign algorithm (signature over the raw message) is
// supported; it needs no BLAKE2b and is accepted by the minisign tool.
const algEd = "Ed"

// KeyID identifies a key pair inside key and signature files.
type KeyID [8]byte

// String returns the key id as minisign prints it (upper-case hex, byte-reversed).
func (k KeyID) String() string {
	var r [8]byte
	for i := range k {
		r[7-i] = k[i]
	}
	return strings.ToUpper(hex.EncodeToString(r[:]))
}

// PublicKey is a release verification key.
type PublicKey struct {
	ID  KeyID
	Key ed25519.PublicKey
}

// SecretKey is a release signing key. Its file holds the base64 seed and key
// id on one line; unlike minisign's own format it is not password-encrypted,
// so CI must supply it from a secret store.
type SecretKey struct {
	ID   KeyID
	Seed []byte
}

// GenerateKey creates a new key pair.
func GenerateKey() (SecretKey, PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SecretKey{}, PublicKey{}, err
	}
	var id KeyID
	if _, err := rand.Read(id[:]); err != nil {
		return SecretKey{}, PublicKey{}, err
	}
	return SecretKey{ID: id, Seed: priv.Seed()}, PublicKey{ID: id, Key: pub}, nil
}

// Public derives the public half.
func (s SecretKey) Public() PublicKey {
	return PublicKey{ID: s.ID, Key: ed25519.NewKeyFromSeed(s.Seed).Public().(ed25519.PublicKey)}
}

// Marshal encodes the public key in minisign's .pub format.
func (p PublicKey) Marshal() []byte {
	raw := append([]byte(algEd), p.ID[:]...)
	raw = append(raw, p.Key...)
	return []byte(fmt.Sprintf("untrusted comment: minisign public key %s\n%s\n", p.ID, base64.StdEncoding.EncodeToString(raw)))
}

// ParsePublicKey decodes a minisign .pub file.
func ParsePublicKey(data []byte) (PublicKey, error) {
	lines := splitLines(data)
	if len(lines) < 2 {
		return PublicKey{}, errors.New("public key: expected comment and key lines")
	}
	raw, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(raw) != 2+8+ed25519.PublicKeySize || string(raw[:2]) != algEd {
		return PublicKey{}, errors.New("public key: malformed or unsupported algorithm")
	}
	var p PublicKey
	copy(p.ID[:], raw[2:10])
	p.Key = ed25519.PublicKey(append([]byte(nil), raw[10:]...))
	return p, nil
}

// Marshal encodes the secret key file.
func (s SecretKey) Marshal() []byte {
	raw := append(append([]byte(nil), s.ID[:]...), s.Seed...)
	return []byte("parley release secret key\n" + base64.StdEncoding.EncodeToString(raw) + "\n")
}

// ParseSecretKey decodes a secret key file.
func ParseSecretKey(data []byte) (SecretKey, error) {
	lines := splitLines(data)
	if len(lines) < 2 || lines[0] != "parley release secret key" {
		return SecretKey{}, errors.New("secret key: unrecognized file")
	}
	raw, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(raw) != 8+ed25519.SeedSize {
		return SecretKey{}, errors.New("secret key: malformed")
	}
	var s SecretKey
	copy(s.ID[:], raw[:8])
	s.Seed = append([]byte(nil), raw[8:]...)
	return s, nil
}

// Sign produces a minisign-format signature file for msg. The trusted comment
// is covered by a second (global) signature.
func (s SecretKey) Sign(msg []byte, trustedComment string) []byte {
	priv := ed25519.NewKeyFromSeed(s.Seed)
	sig := ed25519.Sign(priv, msg)
	global := ed25519.Sign(priv, append(append([]byte(nil), sig...), trustedComment...))
	raw := append(append([]byte(algEd), s.ID[:]...), sig...)
	var b bytes.Buffer
	fmt.Fprintf(&b, "untrusted comment: signature from parley release key %s\n", s.ID)
	fmt.Fprintf(&b, "%s\n", base64.StdEncoding.EncodeToString(raw))
	fmt.Fprintf(&b, "trusted comment: %s\n", trustedComment)
	fmt.Fprintf(&b, "%s\n", base64.StdEncoding.EncodeToString(global))
	return b.Bytes()
}

// Verify checks a signature file against msg and returns the trusted comment.
func (p PublicKey) Verify(msg, sigFile []byte) (string, error) {
	lines := splitLines(sigFile)
	if len(lines) < 4 || !strings.HasPrefix(lines[2], "trusted comment: ") {
		return "", errors.New("signature: malformed file")
	}
	raw, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(raw) != 2+8+ed25519.SignatureSize {
		return "", errors.New("signature: malformed")
	}
	if string(raw[:2]) != algEd {
		return "", errors.New("signature: unsupported algorithm")
	}
	if !bytes.Equal(raw[2:10], p.ID[:]) {
		return "", errors.New("signature: key id does not match the public key")
	}
	sig := raw[10:]
	global, err := base64.StdEncoding.DecodeString(lines[3])
	if err != nil || len(global) != ed25519.SignatureSize {
		return "", errors.New("signature: malformed global signature")
	}
	if !ed25519.Verify(p.Key, msg, sig) {
		return "", errors.New("signature: invalid")
	}
	comment := strings.TrimPrefix(lines[2], "trusted comment: ")
	if !ed25519.Verify(p.Key, append(append([]byte(nil), sig...), comment...), global) {
		return "", errors.New("signature: trusted comment invalid")
	}
	return comment, nil
}

func splitLines(data []byte) []string {
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}
