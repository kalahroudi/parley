// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package adapter

import (
	"os/exec"
	"syscall"
)

// prepare puts the command in a process group of its own, so that killing the group also kills what it started.
func prepare(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// containTree returns the function that kills the command's whole process group.
func containTree(cmd *exec.Cmd) (func(), error) {
	pid := cmd.Process.Pid
	return func() { _ = syscall.Kill(-pid, syscall.SIGKILL) }, nil
}
