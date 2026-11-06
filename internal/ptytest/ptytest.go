// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package ptytest

import (
	"os"
	"os/exec"
	"syscall"
)

// Start runs cmd with the pseudo-terminal as its controlling terminal (a session of its own, the terminal as its
// standard input, output and error) and returns the master side: what is written to it is typed at the terminal, and
// what the process prints can be read from it. The caller reaps cmd and closes the master.
func Start(cmd *exec.Cmd) (*os.File, error) {
	master, slave, err := open()
	if err != nil {
		return nil, err
	}
	defer slave.Close()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		master.Close()
		return nil, err
	}
	return master, nil
}
