// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Command parley-cli is the user-facing Parley command.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kalahroudi/parley/internal/root"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "dev"

//cover:ignore main only wires the process (arguments, config directory, os.Exit) to execute, which is tested
func main() {
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr, os.UserConfigDir))
}

func execute(args []string, out, errw io.Writer, configDir func() (string, error)) int {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(out, "parley-cli", version)
		return 0
	}
	if len(args) >= 2 && args[0] == "admin" && args[1] == "init" {
		dir, err := configDir()
		if err != nil {
			//logx:allow fatal CLI error for the operator's terminal; no task content exists in this process path
			fmt.Fprintln(errw, "error:", err)
			return 1
		}
		dir = filepath.Join(dir, "parley")
		return adminInit(args[2:], out, errw, root.FileStore{Dir: dir}, filepath.Join(dir, "root-backup.json"))
	}
	fmt.Fprintln(errw, "usage: parley-cli --version | admin init [-backup <file>]")
	return 2
}
