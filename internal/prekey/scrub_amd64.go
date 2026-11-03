// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64

package prekey

func hasAVX() bool
func hasAVX512() bool
func scrubSSE()
func scrubAVX()
func scrubAVX512()

// scrubProbe and scrubProbe512 are test hooks (scrub_amd64.s).
func scrubProbe(out *[512]byte, avx bool)
func scrubProbe512(out *[2112]byte)

// haveAVX and haveAVX512 are read by the assembly: scrubAVX and scrubAVX512 do
// nothing when the CPU (or the OS state-saving) lacks the feature, so no
// instruction the CPU cannot decode ever runs.
var (
	haveAVX    = hasAVX()
	haveAVX512 = hasAVX512()
)

// scrubVectorRegisters zeroes the CPU's vector registers (XMM, YMM, ZMM and the
// AVX-512 mask registers, as far as the CPU has them). Key bytes copied
// through them would otherwise sit there until the next vector instruction and
// be written to a signal stack, in the Go heap, by any signal delivered in
// between (the runtime sends SIGURG to preempt, around every garbage collection).
func scrubVectorRegisters() {
	scrubSSE()
	scrubAVX()
	scrubAVX512()
}
