// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
)

// File encryption: a per-file random key, fixed-size chunks sealed with
// AES-256-GCM, a counter nonce and a final-chunk flag in the nonce. Reordering,
// dropping, duplicating or truncating chunks fails to open. The key and the
// plaintext SHA-256 travel inside the task's `inner`; the ciphertext goes to
// R2 under a random object key, so the gateway and R2 see only ciphertext.
const (
	// FileChunkSize is the plaintext size of every chunk except the last.
	FileChunkSize = 64 << 10
	FileKeySize   = 32
	gcmTag        = 16
)

var (
	ErrFileKey  = errors.New("envelope: bad file key")
	ErrFileOpen = errors.New("envelope: cannot open file")
	ErrFileHash = errors.New("envelope: file hash mismatch")
)

// NewFileKey returns a fresh random file key.
func NewFileKey() ([FileKeySize]byte, error) {
	var k [FileKeySize]byte
	_, err := io.ReadFull(rand.Reader, k[:])
	return k, err
}

func fileAEAD(key []byte) (cipher.AEAD, error) {
	// NewCipher rejects every length but 16, 24 and 32; require 32 below.
	b, err := aes.NewCipher(key)
	if err != nil || len(key) != FileKeySize {
		return nil, ErrFileKey
	}
	return cipher.NewGCM(b)
}

// chunkNonce is the 8-byte big-endian chunk index, three zero bytes, and a
// final flag byte.
func chunkNonce(i uint64, final bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n, i)
	if final {
		n[11] = 1
	}
	return n
}

// readChunk reads up to size bytes and reports whether the stream ends there.
func readChunk(r *bufio.Reader, buf []byte) (n int, last bool, err error) {
	n, err = io.ReadFull(r, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return n, true, nil
	}
	if err != nil {
		return n, false, err
	}
	_, perr := r.Peek(1)
	return n, perr == io.EOF, nil
}

// EncryptFile streams src to dst as sealed chunks and returns the SHA-256 of
// the plaintext. An empty file yields one empty final chunk.
func EncryptFile(key []byte, src io.Reader, dst io.Writer) ([HashSize]byte, error) {
	var sum [HashSize]byte
	aead, err := fileAEAD(key)
	if err != nil {
		return sum, err
	}
	h := sha256.New()
	br := bufio.NewReader(src)
	buf := make([]byte, FileChunkSize)
	for i := uint64(0); ; i++ {
		n, last, err := readChunk(br, buf)
		if err != nil {
			return sum, err
		}
		h.Write(buf[:n])
		if _, err := dst.Write(aead.Seal(nil, chunkNonce(i, last), buf[:n], nil)); err != nil {
			return sum, err
		}
		if last {
			break
		}
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// DecryptFile streams sealed chunks from src to dst and checks the plaintext
// hash. Plaintext is written chunk by chunk as each chunk authenticates, so on
// any error the caller must discard what was written; truncation and a wrong
// hash are only detected at the end.
func DecryptFile(key []byte, src io.Reader, dst io.Writer, want [HashSize]byte) error {
	aead, err := fileAEAD(key)
	if err != nil {
		return err
	}
	h := sha256.New()
	br := bufio.NewReader(src)
	buf := make([]byte, FileChunkSize+gcmTag)
	for i := uint64(0); ; i++ {
		n, last, err := readChunk(br, buf)
		if err != nil {
			return err
		}
		pt, err := aead.Open(nil, chunkNonce(i, last), buf[:n], nil)
		if err != nil {
			return ErrFileOpen
		}
		h.Write(pt)
		if _, err := dst.Write(pt); err != nil {
			return err
		}
		if last {
			break
		}
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), want[:]) != 1 {
		return ErrFileHash
	}
	return nil
}
