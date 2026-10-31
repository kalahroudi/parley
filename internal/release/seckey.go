// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

const secretHeader = "parley release secret key (aes-256-gcm, pbkdf2-sha256)"

// kdfIterations is the PBKDF2 cost written into new key files; it is a
// variable only so tests can lower it. Parsing honours the stored value.
var kdfIterations uint32 = 600_000

const (
	maxKDFIterations = 10_000_000
	saltLen          = 16
	nonceLen         = 12
)

// pbkdf2 is PBKDF2-HMAC-SHA256 producing a 32-byte key (one block), kept here
// so the package needs nothing beyond the standard library.
func pbkdf2(password, salt []byte, iter int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < iter; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func gcm(password string, salt []byte, iter uint32) (cipher.AEAD, error) {
	block, err := aes.NewCipher(pbkdf2([]byte(password), salt, int(iter)))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// MarshalEncrypted encodes the secret key file, sealing the seed with a key
// derived from password. The password must not be empty.
func (s SecretKey) MarshalEncrypted(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("secret key: empty password")
	}
	hdr := make([]byte, saltLen+4+nonceLen+len(s.ID))
	salt, rest := hdr[:saltLen], hdr[saltLen:]
	binary.BigEndian.PutUint32(rest[:4], kdfIterations)
	nonce := rest[4 : 4+nonceLen]
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	copy(rest[4+nonceLen:], s.ID[:])
	aead, err := gcm(password, salt, kdfIterations)
	if err != nil {
		return nil, err
	}
	raw := aead.Seal(append([]byte(nil), hdr...), nonce, s.Seed, hdr) // header is authenticated
	return []byte(secretHeader + "\n" + base64.StdEncoding.EncodeToString(raw) + "\n"), nil
}

// ParseSecretKey decrypts a secret key file with password.
func ParseSecretKey(data []byte, password string) (SecretKey, error) {
	lines := splitLines(data)
	if len(lines) != 2 || lines[0] != secretHeader {
		return SecretKey{}, errors.New("secret key: unrecognized file")
	}
	raw, err := base64.StdEncoding.DecodeString(lines[1])
	hdrLen := saltLen + 4 + nonceLen + 8
	if err != nil || len(raw) != hdrLen+ed25519.SeedSize+16 {
		return SecretKey{}, errors.New("secret key: malformed")
	}
	hdr, ct := raw[:hdrLen], raw[hdrLen:]
	iter := binary.BigEndian.Uint32(hdr[saltLen : saltLen+4])
	if iter == 0 || iter > maxKDFIterations {
		return SecretKey{}, errors.New("secret key: bad iteration count")
	}
	aead, err := gcm(password, hdr[:saltLen], iter)
	if err != nil {
		return SecretKey{}, err
	}
	seed, err := aead.Open(nil, hdr[saltLen+4:saltLen+4+nonceLen], ct, hdr)
	if err != nil {
		return SecretKey{}, errors.New("secret key: wrong password or corrupted file")
	}
	var k SecretKey
	copy(k.ID[:], hdr[hdrLen-8:])
	k.Seed = seed
	return k, nil
}
