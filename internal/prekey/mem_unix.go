// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package prekey

import "syscall"

// allocLocked maps n bytes of anonymous memory outside the Go heap and pins it
// in RAM so it is never swapped out.
func allocLocked(n int) ([]byte, error) {
	b, err := syscall.Mmap(-1, 0, n, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	if err := syscall.Mlock(b); err != nil {
		syscall.Munmap(b)
		return nil, err
	}
	return b, nil
}

func freeLocked(b []byte) {
	clear(b)
	syscall.Munlock(b)
	syscall.Munmap(b)
}
