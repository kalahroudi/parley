// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package acceptance

import (
	"os/exec"
	"syscall"
)

// ownGroup starts the command in a process group of its own.
func ownGroup(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000200} } // CREATE_NEW_PROCESS_GROUP

// openSockets: a child process on Windows inherits only the handles Go passes
// explicitly (none here), so there is nothing to list.
func openSockets() []int { return nil }
