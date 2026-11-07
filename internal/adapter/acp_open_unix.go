// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package adapter

import (
	"os"
	"syscall"
)

// openFlags are the flags to open a file the agent asked for. It may have been swapped for a named pipe after the owner
// allowed the call: opening that must not block, so O_NONBLOCK (which does not affect a regular file). A file to write is
// truncated only after it is known to be a regular one.
func openFlags(write bool) int {
	if write {
		return os.O_WRONLY | os.O_CREATE | syscall.O_NONBLOCK
	}
	return os.O_RDONLY | syscall.O_NONBLOCK
}
