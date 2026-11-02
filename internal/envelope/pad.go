// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math/bits"
)

const (
	// MinBucket is the smallest padded size; buckets are powers of two from here.
	MinBucket = 4096
	// MaxPadded is the largest bucket (8 MiB); its AEAD output fits MaxCiphertextSize.
	MaxPadded = 1 << 23
	padMarker = 0x80
)

// ErrPadding means padded plaintext is not in canonical form.
var ErrPadding = errors.New("envelope: bad padding")

// ErrTooLarge means the plaintext does not fit the largest bucket.
var ErrTooLarge = errors.New("envelope: plaintext too large to pad")

// Pad returns plaintext followed by 0x80 and zeros, extended to the smallest
// power-of-two bucket (at least MinBucket) that holds it, so the ciphertext
// length reveals only the bucket.
func Pad(plaintext []byte) ([]byte, error) {
	if len(plaintext) >= MaxPadded {
		return nil, ErrTooLarge
	}
	// Len(L) is the smallest power of two above L, which leaves room for the marker.
	size := max(MinBucket, 1<<bits.Len(uint(len(plaintext))))
	out := make([]byte, size)
	copy(out, plaintext)
	out[len(plaintext)] = padMarker
	return out, nil
}

// Unpad reverses Pad and rejects anything that Pad could not have produced, so
// one plaintext has exactly one padded form.
func Unpad(padded []byte) ([]byte, error) {
	n := len(padded)
	if n < MinBucket || n&(n-1) != 0 {
		return nil, ErrPadding
	}
	end := len(bytes.TrimRight(padded, "\x00"))
	if end == 0 || padded[end-1] != padMarker {
		return nil, ErrPadding
	}
	pt := padded[:end-1]
	// Canonical: the bucket must be the smallest that fits.
	if n > MinBucket && len(pt)+1 <= n/2 {
		return nil, ErrPadding
	}
	return pt, nil
}

// SealPadded pads plaintext to its bucket and seals it as Seal does.
func SealPadded(sign ed25519.PrivateKey, recipient []byte, h Header, plaintext []byte) (*Message, error) {
	p, err := Pad(plaintext)
	if err != nil {
		return nil, ErrInvalid
	}
	return Seal(sign, recipient, h, p)
}

// OpenPadded opens as Open does and strips the padding.
func (m *Message) OpenPadded(recipient []byte) ([]byte, error) {
	p, err := m.Open(recipient)
	if err != nil {
		return nil, err
	}
	return Unpad(p)
}
