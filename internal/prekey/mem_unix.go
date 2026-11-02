// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package prekey

import "syscall"

// sysMap maps n bytes of anonymous memory outside the Go heap.
func sysMap(n int) ([]byte, error) {
	b, err := syscall.Mmap(-1, 0, n, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	// Best effort, defence in depth: Harden's RLIMIT_CORE=0 is the control.
	adviseNoDump(b)
	return b, nil
}

// sysLock pins the region in RAM so it is never swapped out.
func sysLock(b []byte) error { return syscall.Mlock(b) }

// sysUnmap zeroes, unlocks and unmaps the region. Errors leave nothing to act
// on: the bytes are already zero.
func sysUnmap(b []byte) {
	clear(b)
	syscall.Munlock(b)
	syscall.Munmap(b)
}
