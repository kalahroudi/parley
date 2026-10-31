// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Command parleyd is the Parley background daemon.
package main

import (
	"context"
	"fmt"
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

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("parleyd", version)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		//logx:allow fatal startup/CLI error for the operator's terminal; no task content exists in this process path
		fmt.Fprintln(os.Stderr, "parleyd:", err)
		os.Exit(1)
	}
}
