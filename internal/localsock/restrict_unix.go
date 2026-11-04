// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package localsock

import "os"

// restrict closes the socket file to everyone but its owner.
func restrict(path string) error { return os.Chmod(path, 0o600) }
