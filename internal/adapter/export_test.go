// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import "os/exec"

// SetContain replaces the containment of a command and returns the restore.
func SetContain(f func(*exec.Cmd) (func(), error)) func() {
	old := contain
	contain = f
	return func() { contain = old }
}
