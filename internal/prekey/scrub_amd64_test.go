// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64

package prekey

import "testing"

// The scrub must really clear the vector registers: the probe fills them with
// 0xAA, runs the scrub, and reads them back, all in assembly, so the compiler
// cannot touch the registers in between.
func TestScrubVectorRegistersZeroesThem(t *testing.T) {
	for _, avx := range []bool{false, haveAVX} {
		var out [512]byte
		scrubProbe(&out, avx)
		n := 256 // X0-X15
		if avx {
			n = 512 // and the upper halves of Y0-Y15
		}
		for i, b := range out[:n] {
			if b != 0 {
				t.Fatalf("avx=%v: byte %d of the vector state is %#x after the scrub", avx, i, b)
			}
		}
	}
}

// With AVX-512, the scrub must also clear Z0-Z31 (whole registers) and K0-K7.
func TestScrubVectorRegistersZeroesAVX512State(t *testing.T) {
	if !haveAVX512 {
		t.Skip("no AVX-512 on this CPU")
	}
	var out [2112]byte
	scrubProbe512(&out)
	for i, b := range out {
		if b != 0 {
			t.Fatalf("byte %d of the AVX-512 state (Z0-Z31, then K0-K7) is %#x after the scrub", i, b)
		}
	}
}

// The scrub routines must not run an instruction the CPU lacks: with the feature
// flags off they do nothing. Where the CPU does have the feature this is visible,
// because the poisoned state then survives (a CPU without it cannot be poisoned,
// and the probe's own AVX instructions are skipped there).
func TestScrubRoutinesAreGatedOnFeatureFlags(t *testing.T) {
	origAVX, orig512 := haveAVX, haveAVX512
	t.Cleanup(func() { haveAVX, haveAVX512 = origAVX, orig512 })
	if origAVX {
		haveAVX = false
		var out [512]byte
		scrubProbe(&out, true)
		var upper byte
		for _, b := range out[256:] {
			upper |= b
		}
		if upper == 0 {
			t.Fatal("scrubAVX ran although haveAVX is false")
		}
	}
	if orig512 {
		haveAVX512 = false
		var out [2112]byte
		scrubProbe512(&out)
		var all byte
		for _, b := range out {
			all |= b
		}
		if all == 0 {
			t.Fatal("scrubAVX512 ran although haveAVX512 is false")
		}
	}
	scrubVectorRegisters() // with both off it must still be safe to call
}
