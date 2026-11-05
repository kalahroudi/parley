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
	"syscall"

	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/root"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = "usage: parley-cli --version | admin init [-backup <file>] | login -tenant <id> [-gateway <url>] [-provider <name>] [-no-browser] | enroll [-tenant <id> -root <fingerprint> | -trust-on-first-use] [-token] [-replace] [-name <device>] [-key-store keychain|file] | mcp | find [text] | send | get | cancel | list | test -to <device id> [-timeout 30s]"

//cover:ignore main only wires the process (arguments, signals, environment, os.Exit) to execute, which is tested
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.UserConfigDir, os.Getenv, defaultTools())
	stop()
	os.Exit(code)
}

func execute(ctx context.Context, args []string, in io.Reader, out, errw io.Writer, configDir func() (string, error), getenv func(string) string, t tools) int {
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
	if len(args) >= 1 && (args[0] == "login" || args[0] == "enroll") {
		dirs, err := daemon.DefaultDirs(getenv, configDir)
		if err != nil {
			//logx:allow fatal CLI error for the operator's terminal; no task content exists in this process path
			fmt.Fprintln(errw, "error:", err)
			return 1
		}
		if args[0] == "login" {
			return login(ctx, args[1:], out, errw, dirs, getenv, t)
		}
		return enrollCmd(ctx, args[1:], in, out, errw, dirs, getenv, t)
	}
	if len(args) >= 1 && callerCommand(args[0]) {
		return runCaller(ctx, args, in, out, errw, getenv, configDir)
	}
	fmt.Fprintln(errw, usage)
	return 2
}
