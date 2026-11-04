// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"os"

	"golang.org/x/sys/windows"
)

func tryLockFile(f *os.File) (bool, error) {
	ol := new(windows.Overlapped)
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	switch err {
	case nil:
		return true, nil
	case windows.ERROR_LOCK_VIOLATION:
		return false, nil
	default:
		return false, err
	}
}
