// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package fsperm holds the file-system rules the daemon's secrets rest on:
// directories and files that only the current user can reach, verified at every
// open rather than trusted, and the per-device instance lock. The unix and
// Windows halves enforce the same promise with the OS's own access control
// (mode bits and owner; a protected DACL).
package fsperm

import (
	"errors"
	"fmt"
	"os"
)

// ErrLocked means another process holds the lock.
var ErrLocked = errors.New("fsperm: lock held by another process")

// Lock takes an exclusive lock on the file at path (created 0600 if missing)
// without blocking. The OS drops it when the process dies, so a crashed daemon
// never leaves it stale. The returned func releases it.
func Lock(path string) (release func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("fsperm: open lock file: %w", err)
	}
	if err := tryLock(f); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}
