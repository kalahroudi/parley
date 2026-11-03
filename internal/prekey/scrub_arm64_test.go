// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build arm64

package prekey

import "testing"

// The probe fills V0-V31 with 0xAA, scrubs, and reads them back, all in assembly.
func TestScrubVectorRegistersZeroesThem(t *testing.T) {
	var out [512]byte
	scrubProbe(&out)
	for i, b := range out {
		if b != 0 {
			t.Fatalf("byte %d of V0-V31 is %#x after the scrub", i, b)
		}
	}
}
