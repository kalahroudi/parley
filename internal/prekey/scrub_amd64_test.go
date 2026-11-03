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
