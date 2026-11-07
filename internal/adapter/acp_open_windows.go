// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import "os"

// openFlags are the flags to open a file the agent asked for. Windows has no named pipes in the file system that a file
// open could block on.
func openFlags(write bool) int {
	if write {
		return os.O_WRONLY | os.O_CREATE
	}
	return os.O_RDONLY
}
