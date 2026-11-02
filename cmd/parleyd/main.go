// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Command parleyd is the Parley background daemon.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "dev"

// run blocks until ctx is canceled. The daemon's real work lands in later tasks.
func run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

//cover:ignore main only wires the process (arguments, signals, os.Exit) to execute, which is tested
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], os.Stdout, os.Stderr, run)
	stop()
	os.Exit(code)
}

func execute(ctx context.Context, args []string, out, errw io.Writer, runFn func(context.Context) error) int {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(out, "parleyd", version)
		return 0
	}
	if err := runFn(ctx); err != nil {
		//logx:allow fatal startup/CLI error for the operator's terminal; no task content exists in this process path
		fmt.Fprintln(errw, "parleyd:", err)
		return 1
	}
	return 0
}
