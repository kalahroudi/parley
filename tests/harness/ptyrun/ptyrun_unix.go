// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"bytes"
	"errors"
	"io"
	"os/exec"

	"github.com/kalahroudi/parley/internal/ptytest"
)

// drive runs cmd on a pseudo-terminal, copies what it prints to out, types `typed` (and a newline) once `after` has
// been printed, and returns the command's exit code. An error means the terminal or the command could not start, or
// the command could not be waited for.
func drive(cmd *exec.Cmd, out io.Writer, after, typed string) (int, error) {
	master, err := ptytest.Start(cmd)
	if err != nil {
		return 0, err
	}
	defer master.Close()
	var seen []byte
	answered := typed == ""
	buf := make([]byte, 4096)
	for {
		n, err := master.Read(buf)
		out.Write(buf[:n])
		if !answered {
			seen = append(seen, buf[:n]...)
			if bytes.Contains(seen, []byte(after)) {
				answered = true
				master.WriteString(typed + "\n")
			}
		}
		if err != nil { // the command ended (end of file, or an I/O error once the terminal's far side is closed)
			break
		}
	}
	var exit *exec.ExitError
	switch err := cmd.Wait(); {
	case err == nil:
		return 0, nil
	case errors.As(err, &exit):
		return exit.ExitCode(), nil
	default:
		return 0, err
	}
}
