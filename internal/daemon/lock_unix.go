// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package daemon

import (
	"os"
	"syscall"
)

// tryLockFile takes an exclusive advisory lock without blocking. The kernel
// drops it when the process dies, so a crashed daemon never leaves it stale.
func tryLockFile(f *os.File) (bool, error) {
	switch err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err {
	case nil:
		return true, nil
	case syscall.EWOULDBLOCK:
		return false, nil
	default:
		return false, err
	}
}
