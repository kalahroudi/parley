// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"io"
	"os/exec"
)

// drive is not available: Windows has no pseudo-terminal that gives a process a controlling terminal this way.
func drive(*exec.Cmd, io.Writer, string, string) (int, error) { return 0, errors.ErrUnsupported }
