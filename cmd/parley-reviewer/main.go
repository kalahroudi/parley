// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Command parley-reviewer is the reference tool-less reviewer bot: a program for
// the CLI adapter that reads one task on standard input and writes the review to
// standard output. See internal/reviewer for what tool-less means here.
package main

import (
	"io"
	"os"

	"github.com/kalahroudi/parley/internal/reviewer"
)

//cover:ignore main only wires standard input, standard output and os.Exit to run, which is tested; the built binary runs in internal/acceptance (T507)
func main() { os.Exit(run(os.Stdin, os.Stdout)) }

func run(in io.Reader, out io.Writer) int {
	if reviewer.Run(in, out) != nil {
		return 1
	}
	return 0
}
