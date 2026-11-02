// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package binding

import (
	"os"
	"syscall"
)

// tryLock takes an exclusive advisory lock on f without blocking. The kernel
// drops it when the process dies, so a crashed daemon never leaves it stale.
func tryLock(f *os.File) (bool, error) {
	switch err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err {
	case nil:
		return true, nil
	case syscall.EWOULDBLOCK:
		return false, nil
	default:
		return false, err
	}
}

func unlock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
