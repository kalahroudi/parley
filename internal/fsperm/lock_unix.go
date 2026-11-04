// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package fsperm

import (
	"os"
	"syscall"
)

// tryLock takes an exclusive advisory lock without blocking.
func tryLock(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == syscall.EWOULDBLOCK {
		return ErrLocked
	}
	return err
}
