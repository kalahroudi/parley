// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64

package prekey

import "os"

// TEMPORARY (memscan investigation): lets CI compare with and without the scrub.
var scrubOff = os.Getenv("PARLEY_NOSCRUB") != ""

func hasAVX() bool
func scrubSSE()
func scrubAVX()

// scrubProbe is the test hook (scrub_amd64.s).
func scrubProbe(out *[512]byte, avx bool)

var haveAVX = hasAVX()

// scrubVectorRegisters zeroes the CPU's vector registers. Key bytes copied
// through them would otherwise sit there until the next vector instruction and
// be written to a signal stack, in the Go heap, by any signal delivered in
// between (the runtime sends SIGURG to preempt, around every garbage collection).
func scrubVectorRegisters() {
	if scrubOff {
		return
	}
	scrubSSE()
	if haveAVX {
		scrubAVX()
	}
}
