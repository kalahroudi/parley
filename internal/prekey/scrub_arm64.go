// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build arm64

package prekey

func scrubVectorRegisters()

// scrubProbe is the test hook (scrub_arm64.s).
func scrubProbe(out *[512]byte)
