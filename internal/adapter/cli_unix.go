// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package adapter

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxInheritedFD bounds the descriptors looked at: those a parent leaked into the daemon without close-on-exec.
const maxInheritedFD = 4096

// prepare starts the command in a session of its own: it has no controlling terminal (so nothing it runs can ask the
// owner's terminal for anything), and killing its process group also kills what it started. It also marks every descriptor the daemon holds close-on-exec. Go opens its own that way, but one the daemon inherited from
// whatever started it (a socket from a service manager or a CI runner) is not, and the bot would inherit it.
func prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	for fd := 3; fd < maxInheritedFD; fd++ {
		unix.CloseOnExec(fd)
	}
}

// containTree returns the function that kills the command's whole process group.
func containTree(cmd *exec.Cmd) (func(), error) {
	pid := cmd.Process.Pid
	return func() { _ = syscall.Kill(-pid, syscall.SIGKILL) }, nil
}
