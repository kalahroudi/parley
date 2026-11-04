// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package fsperm

import (
	"os"

	"golang.org/x/sys/windows"
)

// tryLock takes an exclusive byte-range lock without blocking.
func tryLock(f *os.File) error {
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
	if err == windows.ERROR_LOCK_VIOLATION {
		return ErrLocked
	}
	return err
}
