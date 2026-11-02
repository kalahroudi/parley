// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package prekey

import (
	"syscall"
	"unsafe"
)

var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procVirtualAlloc  = kernel32.NewProc("VirtualAlloc")
	procVirtualFree   = kernel32.NewProc("VirtualFree")
	procVirtualLock   = kernel32.NewProc("VirtualLock")
	procVirtualUnlock = kernel32.NewProc("VirtualUnlock")
)

const (
	memCommitReserve = 0x3000 // MEM_COMMIT | MEM_RESERVE
	memRelease       = 0x8000
	pageReadWrite    = 0x04
)

// allocLocked commits n bytes outside the Go heap and pins them in RAM.
func allocLocked(n int) ([]byte, error) {
	p, _, err := procVirtualAlloc.Call(0, uintptr(n), memCommitReserve, pageReadWrite)
	if p == 0 {
		return nil, err
	}
	if r, _, err := procVirtualLock.Call(p, uintptr(n)); r == 0 {
		procVirtualFree.Call(p, 0, memRelease)
		return nil, err
	}
	// p is memory VirtualAlloc returned, not a Go pointer; this form keeps go vet quiet.
	return unsafe.Slice(*(**byte)(unsafe.Pointer(&p)), n), nil
}

func freeLocked(b []byte) {
	clear(b)
	p := uintptr(unsafe.Pointer(&b[0]))
	procVirtualUnlock.Call(p, uintptr(len(b)))
	procVirtualFree.Call(p, 0, memRelease)
}
