// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package ttyconfirm

import (
	"os/exec"
	"syscall"
)

// detach starts the command in a session of its own, with no controlling terminal: how the CLI adapter starts a bot.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
