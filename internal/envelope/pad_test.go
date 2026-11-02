// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"errors"
	"testing"
)

func TestPadBuckets(t *testing.T) {
	for _, c := range []struct{ in, out int }{
		{0, 4096}, {1, 4096}, {4094, 4096}, {4095, 4096}, {4096, 8192},
		{8191, 8192}, {8192, 16384}, {1<<23 - 1, 1 << 23},
	} {
		p, err := Pad(make([]byte, c.in))
		if err != nil || len(p) != c.out {
			t.Fatalf("Pad(%d): len %d err %v, want %d", c.in, len(p), err, c.out)
		}
		pt, err := Unpad(p)
		if err != nil || len(pt) != c.in {
			t.Fatalf("Unpad(%d): len %d err %v", c.in, len(pt), err)
		}
	}
}

func TestPadRoundTripKeepsTrailingZeros(t *testing.T) {
	in := []byte{1, 2, 0, 0, 0x80, 0}
	p, _ := Pad(in)
	out, err := Unpad(p)
	if err != nil || !bytes.Equal(in, out) {
		t.Fatalf("got %v %v", out, err)
	}
}

func TestPadTooLarge(t *testing.T) {
	if _, err := Pad(make([]byte, MaxPadded)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestUnpadRejectsNonCanonical(t *testing.T) {
	good, _ := Pad([]byte("x"))
	big := make([]byte, 8192)
	big[10] = padMarker // fits the 4096 bucket, so 8192 is not canonical
	edge := make([]byte, 8192)
	edge[4095] = padMarker // 4095 bytes of plaintext still fit the 4096 bucket
	noMarker := make([]byte, 4096)
	zeroMarker := make([]byte, 4096)
	zeroMarker[5] = 1
	huge := make([]byte, 2*MaxPadded)
	huge[MaxPadded+5] = padMarker // canonical size-wise, but Pad refuses this plaintext
	for name, p := range map[string][]byte{
		"too big":     huge,
		"empty":       nil,
		"short":       good[:100],
		"not pow2":    make([]byte, 5000),
		"all zero":    noMarker,
		"no marker":   zeroMarker,
		"oversized":   big,
		"edge":        edge,
		"bad pow2 sz": append(append([]byte{}, good...), 0),
	} {
		if _, err := Unpad(p); !errors.Is(err, ErrPadding) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestSealPaddedHidesLengthWithinBucket(t *testing.T) {
	k := newKeys(t)
	h := taskHeader()
	a, err := SealPadded(k.sign, k.prekeyPub, h, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealPadded(k.sign, k.prekeyPub, h, bytes.Repeat([]byte("y"), 4000))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Ciphertext) != len(b.Ciphertext) || len(a.Ciphertext) != MinBucket+ciphertextOverhead {
		t.Fatalf("ciphertext sizes %d %d", len(a.Ciphertext), len(b.Ciphertext))
	}
	pt, err := a.OpenPadded(k.prekeyPriv)
	if err != nil || string(pt) != "hi" {
		t.Fatalf("got %q %v", pt, err)
	}
}

func TestSealPaddedErrors(t *testing.T) {
	k := newKeys(t)
	if _, err := SealPadded(k.sign, k.prekeyPub, taskHeader(), make([]byte, MaxPadded)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestOpenPaddedErrors(t *testing.T) {
	k := newKeys(t)
	h := taskHeader()
	m, _ := SealPadded(k.sign, k.prekeyPub, h, []byte("hi"))
	if _, err := m.OpenPadded(make([]byte, 5)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad key: %v", err)
	}
	// Sealed without padding: opens, but is not canonical padded form.
	raw, _ := Seal(k.sign, k.prekeyPub, h, []byte("hi"))
	if _, err := raw.OpenPadded(k.prekeyPriv); !errors.Is(err, ErrPadding) {
		t.Fatalf("unpadded: %v", err)
	}
}

// FuzzUnpad feeds arbitrary bytes to the unpadder. Nothing may panic, and
// anything it accepts must re-pad to exactly the same bytes.
func FuzzUnpad(f *testing.F) {
	for _, n := range []int{0, 1, 4095, 4096, 9000} {
		p, _ := Pad(make([]byte, n))
		f.Add(p)
	}
	f.Add([]byte{})
	f.Add(make([]byte, MinBucket))
	f.Fuzz(func(t *testing.T, b []byte) {
		pt, err := Unpad(b)
		if err != nil {
			if pt != nil {
				t.Fatal("plaintext returned with an error")
			}
			return
		}
		again, err := Pad(pt)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatal("accepted padding is not canonical")
		}
	})
}
