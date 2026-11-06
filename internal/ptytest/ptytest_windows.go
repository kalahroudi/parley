// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ptytest

import (
	"errors"
	"os"
	"os/exec"
)

// Start is not available: Windows has no pseudo-terminal that gives a process a controlling terminal this way.
func Start(*exec.Cmd) (*os.File, error) { return nil, errors.ErrUnsupported }
