// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package ttydev

import (
	"io"
	"os"
)

// Open opens the process's controlling terminal. It fails when there is none (ENXIO), which is the case for a
// process in a session that never had one.
func Open() (io.ReadWriter, func(), error) { return openPath("/dev/tty") }

func openPath(path string) (io.ReadWriter, func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}
