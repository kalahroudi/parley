// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package prekey

import (
	"math"
	"math/bits"
	"syscall"
	"testing"
	"unsafe"
)

// beyondMapping returns a slice that starts inside the mapping b and runs far
// past its end, so the range always includes unmapped addresses. Unlike
// unmapping b and reusing it, no other thread can map the range meanwhile, so
// the system calls on it fail deterministically.
func beyondMapping(b []byte) []byte {
	n := math.MaxInt >> 20 // 8 TiB on 64-bit systems
	if bits.UintSize == 32 {
		n = 1 << 30 // MaxInt>>20 would be 2 KiB, inside the page
	}
	return unsafe.Slice(&b[0], n)
}

func TestSysMapLockUnmap(t *testing.T) {
	b, err := sysMap(4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := sysLock(b); err != nil {
		t.Fatalf("this OS must be able to lock a page: %v", err)
	}
	b[0] = 1

	if _, err := sysMap(math.MaxInt); err == nil {
		t.Fatal("impossible mapping succeeded")
	}
	// Locking a range that is not all mapped fails and says so.
	if err := sysLock(beyondMapping(b)); err == nil {
		t.Fatal("locking unmapped memory succeeded")
	}
	sysUnmap(b)
}

func TestSetCoreLimitError(t *testing.T) {
	if err := setCoreLimit(&syscall.Rlimit{Cur: 1, Max: 0}); err == nil {
		t.Fatal("cur > max accepted")
	}
}
