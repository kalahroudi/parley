// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package prekey

import (
	"math"
	"testing"
	"unsafe"
)

const (
	memReserve   = 0x2000
	pageNoAccess = 0x01
)

func TestSysMapLockUnmap(t *testing.T) {
	b, err := sysMap(4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := sysLock(b); err != nil {
		t.Fatalf("this OS must be able to lock a page: %v", err)
	}
	b[0] = 1
	sysUnmap(b)

	if _, err := sysMap(math.MaxInt); err == nil {
		t.Fatal("impossible allocation succeeded")
	}
}

// VirtualLock refuses pages that are reserved but not committed. The range
// stays reserved by this test until it is released, so no other thread can
// take it meanwhile and the failure is deterministic. (A range freed with
// VirtualFree can be handed to another allocation at once.)
func TestSysLockFailsOnUncommitted(t *testing.T) {
	p, _, err := procVirtualAlloc.Call(0, 4096, memReserve, pageNoAccess)
	if p == 0 {
		t.Fatal(err)
	}
	defer procVirtualFree.Call(p, 0, memRelease)
	b := unsafe.Slice(*(**byte)(unsafe.Pointer(&p)), 4096)
	if err := sysLock(b); err == nil {
		t.Fatal("locking uncommitted memory succeeded")
	}
}
