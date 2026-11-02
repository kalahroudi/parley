// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package root creates and recovers the tenant signing root: an Ed25519 key,
// its fingerprint, a recovery code and an encrypted backup of the key.
package root

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	backupVersion  = 1
	pbkdf2Rounds   = 600_000
	recoveryBytes  = 20 // 160 bits; high entropy, so PBKDF2 only adds cost.
	saltBytes      = 16
	fingerprintLen = 26 // base32 chars of SHA-256, 130 bits.
)

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrBadRecovery is returned when the recovery code or backup does not open.
var ErrBadRecovery = errors.New("root: recovery code does not open this backup")

// Root is a freshly generated tenant signing root.
type Root struct {
	Private      ed25519.PrivateKey
	Public       ed25519.PublicKey
	Fingerprint  string
	RecoveryCode string
	Backup       []byte
}

// Fingerprint is the pinned form of a root public key, grouped for reading aloud.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return group(enc.EncodeToString(sum[:])[:fingerprintLen])
}

// New generates a root key, a recovery code and the encrypted backup.
func New() (*Root, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, recoveryBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	code := group(enc.EncodeToString(raw))
	backup, err := seal(code, priv.Seed(), pub)
	if err != nil {
		return nil, err
	}
	return &Root{Private: priv, Public: pub, Fingerprint: Fingerprint(pub), RecoveryCode: code, Backup: backup}, nil
}

// Recover opens a backup with the recovery code and returns the root key.
func Recover(code string, backup []byte) (ed25519.PrivateKey, error) {
	var b backupFile
	if err := json.Unmarshal(backup, &b); err != nil || b.Version != backupVersion || b.Rounds != pbkdf2Rounds {
		return nil, ErrBadRecovery
	}
	aead, err := aeadFor(code, b.Salt, b.Rounds)
	if err != nil {
		return nil, ErrBadRecovery
	}
	if len(b.Nonce) != aead.NonceSize() {
		return nil, ErrBadRecovery
	}
	seed, err := aead.Open(nil, b.Nonce, b.Ciphertext, b.Public)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrBadRecovery
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if string(priv.Public().(ed25519.PublicKey)) != string(b.Public) {
		return nil, ErrBadRecovery
	}
	return priv, nil
}

type backupFile struct {
	Version    int    `json:"version"`
	Rounds     int    `json:"pbkdf2_rounds"`
	Public     []byte `json:"public"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func seal(code string, seed []byte, pub ed25519.PublicKey) ([]byte, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := aeadFor(code, salt, pbkdf2Rounds)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return json.Marshal(backupFile{
		Version: backupVersion, Rounds: pbkdf2Rounds, Public: pub, Salt: salt, Nonce: nonce,
		Ciphertext: aead.Seal(nil, nonce, seed, pub),
	})
}

func aeadFor(code string, salt []byte, rounds int) (cipher.AEAD, error) {
	norm := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(code))
	key, err := pbkdf2.Key(sha256.New, norm, salt, rounds, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func group(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	parts = append(parts, s)
	return strings.Join(parts, "-")
}

func (r *Root) String() string { return fmt.Sprintf("root(%s)", r.Fingerprint) }
