// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ttyconfirm

import (
	"os/exec"
	"syscall"
)

// detach starts the command with no console of its own and none inherited.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000008} } // DETACHED_PROCESS
