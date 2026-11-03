// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build unix && !linux

package acceptance

// There is no portable way to read a process's own address space here (macOS
// needs Mach task ports), so the address-space scan runs on Linux only and CI
// runs it there. The core-limit and lock checks run everywhere.

import "testing"

func vmLockedKB() int { return 0 }

func scanChild(*childReport) { panic("address-space scan is linux-only") }

func TestAddressSpaceHoldsNoErasedKey(t *testing.T) {
	t.Skip("address-space scan reads /proc/self/mem: linux only")
}
