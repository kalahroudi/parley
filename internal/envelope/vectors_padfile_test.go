// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// testdata/vectors_padfile.json publishes the padding and file-chunk formats.
// Both are deterministic (a fixed file key, counter nonces), so unlike the
// message vectors they are reproduced byte for byte. verify_vectors.py checks
// the same file without sharing code. Changing it is a wire-format change;
// regenerate with PARLEY_UPDATE_VECTORS=1 and see vectors.lock.
type padVector struct {
	PlaintextLen int    `json:"plaintext_len"`
	PaddedLen    int    `json:"padded_len"`
	PaddedSHA256 string `json:"padded_sha256"`
}

type rejectVector struct {
	Name string `json:"name"`
	Why  string `json:"why"`
}

type fileVector struct {
	Name            string `json:"name"`
	PlaintextLen    int    `json:"plaintext_len"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
	CiphertextLen   int    `json:"ciphertext_len"`
	CiphertextSHA   string `json:"ciphertext_sha256"`
	Ciphertext      string `json:"ciphertext,omitempty"` // only when small
}

type padFileVectors struct {
	Description string         `json:"description"`
	PadPattern  string         `json:"plaintext_pattern"`
	FileKey     string         `json:"file_key"`
	Pad         []padVector    `json:"pad"`
	PadReject   []rejectVector `json:"pad_reject"`
	File        []fileVector   `json:"file"`
}

// vectorPlaintext is byte i = i mod 251, so any language can regenerate it.
func vectorPlaintext(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i % 251)
	}
	return p
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

var (
	padLens  = []int{0, 1, 100, 4094, 4095, 4096, 5000, 8191, 8192}
	fileLens = []struct {
		name string
		n    int
	}{{"empty", 0}, {"one-byte", 1}, {"small", 5000}, {"exact-chunk", FileChunkSize}, {"two-chunks", FileChunkSize + 1}, {"three-chunks", 2*FileChunkSize + 7}}
	// Rejected paddings the Python verifier constructs from the "name".
	padRejects = []rejectVector{
		{"all-zeros-4096", "no 0x80 marker"},
		{"short-4095", "shorter than the smallest bucket"},
		{"not-power-of-two-4097", "length is not a power of two"},
		{"noncanonical-bucket", "8192 bytes holding 100 bytes of plaintext: the bucket is not the smallest that fits"},
		{"marker-not-last", "bytes other than zero after the marker"},
	}
)

const fileVectorKeyByte = 0x33

func buildPadFileVectors(t *testing.T) padFileVectors {
	t.Helper()
	f := padFileVectors{
		Description: "Parley padding and file-chunk vectors. plaintext = byte i is i mod 251. pad: Pad(plaintext) = plaintext || 0x80 || zeros up to the smallest " +
			"power-of-two bucket of at least 4096 bytes. pad_reject: constructions Unpad must refuse. file: EncryptFile with the fixed key; plaintext is zero-padded " +
			"to its bucket and cut into 65536-byte chunks, each sealed AES-256-GCM with nonce = u64 index || 3 zero bytes || final flag and aad = \"parley/file/v1\" || nonce. " +
			"Fully deterministic.",
		PadPattern: "i mod 251",
		FileKey:    hex.EncodeToString(bytes.Repeat([]byte{fileVectorKeyByte}, FileKeySize)),
		PadReject:  padRejects,
	}
	for _, n := range padLens {
		p, err := Pad(vectorPlaintext(n))
		if err != nil {
			t.Fatal(err)
		}
		f.Pad = append(f.Pad, padVector{n, len(p), sha(p)})
	}
	key := bytes.Repeat([]byte{fileVectorKeyByte}, FileKeySize)
	for _, c := range fileLens {
		pt := vectorPlaintext(c.n)
		var ct bytes.Buffer
		if _, _, err := EncryptFile(key, bytes.NewReader(pt), &ct); err != nil {
			t.Fatal(err)
		}
		v := fileVector{c.name, c.n, sha(pt), ct.Len(), sha(ct.Bytes()), ""}
		if ct.Len() <= 8192 {
			v.Ciphertext = hex.EncodeToString(ct.Bytes())
		}
		f.File = append(f.File, v)
	}
	return f
}

func TestPublishedPadFileVectors(t *testing.T) {
	want := buildPadFileVectors(t)
	if os.Getenv("PARLEY_UPDATE_VECTORS") == "1" {
		out, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile("testdata/vectors_padfile.json", append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile("testdata/vectors_padfile.json")
	if err != nil {
		t.Fatal(err)
	}
	var got padFileVectors
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	// The published file must equal what the code produces today, byte for byte.
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if !bytes.Equal(g, w) {
		t.Fatal("padding or file format no longer matches testdata/vectors_padfile.json: that is a wire-format change")
	}
	for _, v := range got.Pad {
		p, err := Pad(vectorPlaintext(v.PlaintextLen))
		if err != nil || len(p) != v.PaddedLen || sha(p) != v.PaddedSHA256 {
			t.Fatalf("pad %d: %v", v.PlaintextLen, err)
		}
		if pt, err := Unpad(p); err != nil || !bytes.Equal(pt, vectorPlaintext(v.PlaintextLen)) {
			t.Fatalf("unpad %d: %v", v.PlaintextLen, err)
		}
	}
	for _, r := range padRejects {
		if _, err := Unpad(rejectedPadding(r.Name)); !errors.Is(err, ErrPadding) {
			t.Fatalf("%s: %v", r.Name, err)
		}
	}
	key := unhex(t, got.FileKey)
	for _, v := range got.File {
		pt := vectorPlaintext(v.PlaintextLen)
		var ct bytes.Buffer
		sum, size, err := EncryptFile(key, bytes.NewReader(pt), &ct)
		if err != nil || hex.EncodeToString(sum[:]) != v.PlaintextSHA256 || size != uint64(v.PlaintextLen) ||
			ct.Len() != v.CiphertextLen || sha(ct.Bytes()) != v.CiphertextSHA {
			t.Fatalf("file %s: %v", v.Name, err)
		}
		if v.Ciphertext != "" && hex.EncodeToString(ct.Bytes()) != v.Ciphertext {
			t.Fatalf("file %s: ciphertext differs", v.Name)
		}
		var out bytes.Buffer
		if err := decryptFile(key, bytes.NewReader(ct.Bytes()), &out, sum, size); err != nil || !bytes.Equal(out.Bytes(), pt) {
			t.Fatalf("file %s: open: %v", v.Name, err)
		}
	}
}

// rejectedPadding builds each pad_reject input; verify_vectors.py builds the same.
func rejectedPadding(name string) []byte {
	switch name {
	case "all-zeros-4096":
		return make([]byte, 4096)
	case "short-4095":
		p := make([]byte, 4095)
		p[0] = padMarker
		return p
	case "not-power-of-two-4097":
		p := make([]byte, 4097)
		p[0] = padMarker
		return p
	case "noncanonical-bucket":
		p := make([]byte, 8192)
		p[100] = padMarker
		return p
	case "marker-not-last":
		p := make([]byte, 4096)
		p[10], p[20] = padMarker, 0x01
		return p
	}
	panic("unknown reject vector " + name)
}
