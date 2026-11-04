// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package localsock

import "os"

// chmod is a seam so a test can make restricting the socket fail.
var chmod = os.Chmod

// restrict closes the socket file to everyone but its owner.
func restrict(path string) error { return chmod(path, 0o600) }
