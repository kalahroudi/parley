// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"testing"
)

func encrypt(t *testing.T, key, pt []byte) ([]byte, [HashSize]byte) {
	t.Helper()
	var ct bytes.Buffer
	sum, err := EncryptFile(key, bytes.NewReader(pt), &ct)
	if err != nil {
		t.Fatal(err)
	}
	return ct.Bytes(), sum
}

func fileKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewFileKey()
	if err != nil {
		t.Fatal(err)
	}
	return k[:]
}

func TestFileRoundTripSizes(t *testing.T) {
	key := fileKey(t)
	for _, n := range []int{0, 1, FileChunkSize - 1, FileChunkSize, FileChunkSize + 1, 3 * FileChunkSize, 3*FileChunkSize + 7} {
		pt := make([]byte, n)
		rand.Read(pt)
		ct, sum := encrypt(t, key, pt)
		chunks := max((n+FileChunkSize-1)/FileChunkSize, 1)
		if want := n + chunks*gcmTag; len(ct) != want {
			t.Fatalf("n=%d: ciphertext %d, want %d", n, len(ct), want)
		}
		if sum != sha256.Sum256(pt) {
			t.Fatalf("n=%d: wrong hash", n)
		}
		var out bytes.Buffer
		if err := DecryptFile(key, bytes.NewReader(ct), &out, sum); err != nil || !bytes.Equal(out.Bytes(), pt) {
			t.Fatalf("n=%d: %v", n, err)
		}
	}
}

func TestFileCiphertextHidesContent(t *testing.T) {
	canary := strings.Repeat("CANARY-FILE-CONTENT ", 10)
	ct, _ := encrypt(t, fileKey(t), []byte(canary))
	if bytes.Contains(ct, []byte("CANARY")) {
		t.Fatal("plaintext visible in ciphertext")
	}
}

func TestFileTamperingRejected(t *testing.T) {
	key := fileKey(t)
	pt := make([]byte, 3*FileChunkSize+100)
	rand.Read(pt)
	ct, sum := encrypt(t, key, pt)
	cs := FileChunkSize + gcmTag
	flip := append([]byte(nil), ct...)
	flip[5] ^= 1
	swap := append([]byte(nil), ct...)
	copy(swap[:cs], ct[cs:2*cs])
	copy(swap[cs:2*cs], ct[:cs])
	for name, c := range map[string][]byte{
		"bit flip":          flip,
		"reordered":         swap,
		"truncated at edge": ct[:2*cs],
		"truncated mid":     ct[:len(ct)-1],
		"dropped chunk":     append(append([]byte(nil), ct[:cs]...), ct[2*cs:]...),
		"duplicated chunk":  append(append([]byte(nil), ct[:cs]...), ct[:cs]...),
		"extra after final": append(append([]byte(nil), ct...), ct[:cs]...),
		"empty":             nil,
	} {
		if err := DecryptFile(key, bytes.NewReader(c), io.Discard, sum); !errors.Is(err, ErrFileOpen) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestFileWrongKeyAndHash(t *testing.T) {
	key := fileKey(t)
	ct, sum := encrypt(t, key, []byte("hello"))
	if err := DecryptFile(fileKey(t), bytes.NewReader(ct), io.Discard, sum); !errors.Is(err, ErrFileOpen) {
		t.Fatalf("wrong key: %v", err)
	}
	sum[0] ^= 1
	if err := DecryptFile(key, bytes.NewReader(ct), io.Discard, sum); !errors.Is(err, ErrFileHash) {
		t.Fatalf("wrong hash: %v", err)
	}
}

func TestFileBadKey(t *testing.T) {
	var sum [HashSize]byte
	// 16 bytes is a valid AES key but not a valid file key.
	if _, err := EncryptFile(make([]byte, 16), strings.NewReader("x"), io.Discard); !errors.Is(err, ErrFileKey) {
		t.Fatalf("aes-128 length: %v", err)
	}
	if _, err := EncryptFile(make([]byte, 5), strings.NewReader("x"), io.Discard); !errors.Is(err, ErrFileKey) {
		t.Fatalf("encrypt: %v", err)
	}
	if err := DecryptFile(make([]byte, 5), strings.NewReader("x"), io.Discard, sum); !errors.Is(err, ErrFileKey) {
		t.Fatalf("decrypt: %v", err)
	}
}

var errBoom = errors.New("boom")

type errReader struct{ after int }

func (e *errReader) Read(p []byte) (int, error) {
	if e.after <= 0 {
		return 0, errBoom
	}
	n := min(len(p), e.after)
	e.after -= n
	return n, nil
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errBoom }

func TestFileIOErrors(t *testing.T) {
	key := fileKey(t)
	if _, err := EncryptFile(key, &errReader{after: 10}, io.Discard); !errors.Is(err, errBoom) {
		t.Fatalf("read: %v", err)
	}
	if _, err := EncryptFile(key, strings.NewReader("x"), errWriter{}); !errors.Is(err, errBoom) {
		t.Fatalf("encrypt write: %v", err)
	}
	ct, sum := encrypt(t, key, []byte("x"))
	if err := DecryptFile(key, &errReader{}, io.Discard, sum); !errors.Is(err, errBoom) {
		t.Fatalf("decrypt read: %v", err)
	}
	if err := DecryptFile(key, bytes.NewReader(ct), errWriter{}, sum); !errors.Is(err, errBoom) {
		t.Fatalf("decrypt write: %v", err)
	}
	// A full chunk followed by a read error: the error surfaces on the next chunk.
	if _, err := EncryptFile(key, &errReader{after: FileChunkSize}, io.Discard); !errors.Is(err, errBoom) {
		t.Fatalf("lookahead: %v", err)
	}
}
