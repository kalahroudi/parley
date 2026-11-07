// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"io"
	"os"
	"os/exec"
)

// SetContain replaces the containment of a command and returns the restore.
func SetContain(f func(*exec.Cmd) (func(), error)) func() {
	old := contain
	contain = f
	return func() { contain = old }
}

// SetFileIO replaces the reading and writing of files and returns the restore.
func SetFileIO(r func(io.Reader) ([]byte, error), w func(*os.File, string) error) func() {
	oldR, oldW := readAll, writeAll
	readAll, writeAll = r, w
	return func() { readAll, writeAll = oldR, oldW }
}
