// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Command ptyrun runs a command with a pseudo-terminal as its controlling terminal, the way a person at a terminal
// window would: it waits until the command has printed a given text, types an answer, and passes the command's output
// and exit code on. The walking-skeleton test (tests/walking-skeleton.test.mjs) uses it to answer `parley-cli approve`,
// which asks on the controlling terminal and nowhere else, so a plain pipe cannot. Linux and macOS only; for tests only.
//
//	ptyrun -after "Type yes" -type yes -- parley-cli approve <id>
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

func main() { os.Exit(serve(os.Args[1:], os.Stdout, os.Stderr)) }

// serve returns the command's exit code, or 2 for a usage error and 125 when the terminal or the command could not start.
func serve(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("ptyrun", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	after := fs.String("after", "", "type the answer once the command has printed this text")
	typed := fs.String("type", "", "the answer to type (a newline is added)")
	limit := fs.Duration("timeout", 60*time.Second, "kill the command after this long")
	if err := fs.Parse(args); err != nil || fs.NArg() == 0 {
		fmt.Fprintln(errw, "usage: ptyrun [-after text] [-type answer] [-timeout d] -- command [args]")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, fs.Arg(0), fs.Args()[1:]...)
	exit, err := drive(cmd, out, *after, *typed)
	if err != nil {
		fmt.Fprintln(errw, "ptyrun:", err)
		return 125
	}
	return exit
}
