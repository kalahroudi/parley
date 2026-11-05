// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Command parley-cli is the user-facing Parley command.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/kalahroudi/parley/internal/root"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = "usage: parley-cli --version | admin init [-backup <file>] | mcp | find [text] | send | get | cancel | list"

//cover:ignore main only wires the process (arguments, signals, os.Exit) to execute, which is tested
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv, os.UserConfigDir)
	stop()
	os.Exit(code)
}

func execute(ctx context.Context, args []string, in io.Reader, out, errw io.Writer, getenv func(string) string, configDir func() (string, error)) int {
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
	if len(args) >= 1 && callerCommand(args[0]) {
		return runCaller(ctx, args, in, out, errw, getenv, configDir)
	}
	fmt.Fprintln(errw, usage)
	return 2
}
