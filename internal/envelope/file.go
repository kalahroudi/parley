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
	"math/bits"
)

// File encryption: a per-file random key, fixed-size chunks sealed with
// AES-256-GCM, a counter nonce and a final-chunk flag in the nonce (both also
// in the AAD). Reordering, dropping, duplicating or truncating chunks fails to
// open; a chunk from another file fails because every file has its own key. The
// plaintext is zero-padded to a power-of-two bucket, so the object size in R2
// reveals only the bucket. The key, the plaintext SHA-256 and the true size
// travel inside the task's `inner`; the ciphertext goes to R2 under a random
// object key, so the gateway and R2 see only ciphertext and no file name.
//
// The chunk total cannot be bound into the first chunks' AAD because a
// streaming sender does not know it yet; the final flag and the receiver's
// size check bind it instead. Nothing here touches disk: callers own the
// reader and writer and must discard what the writer received on any error.
const (
	// FileChunkSize is the plaintext size of every chunk except the last.
	FileChunkSize = 64 << 10
	FileKeySize   = 32
	// MaxFileSize bounds a file's plaintext (and so its bucket) to 1 GiB, which
	// caps decrypt work and stops a hostile object from running on forever.
	MaxFileSize = 1 << 30
	gcmTag      = 16
	fileAAD     = "parley/file/v1"
)

var (
	ErrFileKey      = errors.New("envelope: bad file key")
	ErrFileOpen     = errors.New("envelope: cannot open file")
	ErrFileHash     = errors.New("envelope: file hash mismatch")
	ErrFileTooLarge = errors.New("envelope: file too large")
)

// NewFileKey returns a fresh random file key.
func NewFileKey() ([FileKeySize]byte, error) {
	var k [FileKeySize]byte
	_, err := io.ReadFull(rand.Reader, k[:])
	return k, err
}

// FileBucket is the padded plaintext size of a file of the given size: the next
// power of two, at least MinBucket. Sizes above MaxFileSize have no bucket.
func FileBucket(size uint64) (uint64, error) {
	if size > MaxFileSize {
		return 0, ErrFileTooLarge
	}
	return 1 << bits.Len64(max(size, MinBucket)-1), nil
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
// final flag byte. A key encrypts one file, so a nonce never repeats.
func chunkNonce(i uint64, final bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n, i)
	if final {
		n[11] = 1
	}
	return n
}

// chunkAAD binds the domain, the chunk index and the final flag.
func chunkAAD(i uint64, final bool) []byte {
	return append([]byte(fileAAD), chunkNonce(i, final)...)
}

// readChunk reads up to len(buf) bytes and reports whether the stream ends there.
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

// EncryptFile streams src to dst as sealed chunks, zero-padded to the file's
// bucket, and returns the SHA-256 and size of the plaintext (without padding).
// An empty file yields one chunk of padding. Memory use is one chunk.
func EncryptFile(key []byte, src io.Reader, dst io.Writer) (sum [HashSize]byte, size uint64, err error) {
	aead, err := fileAEAD(key)
	if err != nil {
		return sum, 0, err
	}
	h := sha256.New()
	br := bufio.NewReader(src)
	buf := make([]byte, FileChunkSize)
	defer clear(buf)
	var target uint64 // padded size, known once src is exhausted
	done := false
	for i := uint64(0); ; i++ {
		n := 0
		if !done {
			var last bool
			n, last, err = readChunk(br, buf)
			if err != nil {
				return sum, 0, err
			}
			size += uint64(n)
			if target, err = FileBucket(size); err != nil {
				return sum, 0, err
			}
			h.Write(buf[:n])
			done = last
		}
		pn := n
		final := false
		if done {
			// Buckets are powers of two, so past the first chunk the remainder is
			// always a whole number of chunks.
			pn = int(min(FileChunkSize, target))
			clear(buf[n:pn])
			final = (i+1)*FileChunkSize >= target
		}
		if _, err := dst.Write(aead.Seal(nil, chunkNonce(i, final), buf[:pn], chunkAAD(i, final))); err != nil {
			return sum, 0, err
		}
		if final {
			break
		}
	}
	copy(sum[:], h.Sum(nil))
	return sum, size, nil
}

// DecryptFile streams sealed chunks from src to dst and checks the plaintext
// hash. size is the true plaintext size from the task's `inner`: exactly that
// many bytes are written, the rest of the bucket must be zeros, and the object
// must be exactly one bucket long, so extra or missing data is rejected
// without reading further than the bucket. Plaintext is written chunk by chunk
// as each chunk authenticates, so on any error the caller must discard what
// was written; a wrong hash is only detected at the end.
func DecryptFile(key []byte, src io.Reader, dst io.Writer, want [HashSize]byte, size uint64) error {
	aead, err := fileAEAD(key)
	if err != nil {
		return err
	}
	target, err := FileBucket(size)
	if err != nil {
		return err
	}
	h := sha256.New()
	br := bufio.NewReader(src)
	buf := make([]byte, FileChunkSize+gcmTag)
	defer clear(buf)
	var off uint64 // plaintext bytes seen, data and padding
	for i := uint64(0); ; i++ {
		n, last, err := readChunk(br, buf)
		if err != nil {
			return err
		}
		pt, err := aead.Open(buf[:0], chunkNonce(i, last), buf[:n], chunkAAD(i, last))
		if err != nil || uint64(len(pt)) > target-off {
			return ErrFileOpen
		}
		data := pt[:min(uint64(len(pt)), size-min(size, off))]
		for _, b := range pt[len(data):] {
			if b != 0 {
				return ErrFileOpen
			}
		}
		h.Write(data)
		if _, err := dst.Write(data); err != nil {
			return err
		}
		off += uint64(len(pt))
		if last {
			if off != target {
				return ErrFileOpen
			}
			break
		}
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), want[:]) != 1 {
		return ErrFileHash
	}
	return nil
}
