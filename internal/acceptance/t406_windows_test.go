// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package acceptance

import (
	"os/exec"
	"syscall"
)

// childAttrs sets how a bot starts its own child. A child of a process with no console is given a console of its own
// unless it is detached, and a program that makes itself a console is the case the README names; this attack is about
// the console the owner is at, so the child stays detached, in a process group of its own if asked. The daemon's job
// check is what covers the other case.
func childAttrs(c *exec.Cmd, ownGroup bool) {
	flags := uint32(0x00000008) // DETACHED_PROCESS
	if ownGroup {
		flags |= 0x00000200 // CREATE_NEW_PROCESS_GROUP
	}
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags}
}

// openSockets: a child process on Windows inherits only the handles Go passes
// explicitly (none here), so there is nothing to list.
func openSockets() []int { return nil }
