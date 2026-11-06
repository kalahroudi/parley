// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package ttyconfirm asks the person at the keyboard a yes/no question on the
// process's controlling terminal (/dev/tty on Linux and macOS, the console
// CONIN$/CONOUT$ on Windows), and nowhere else.
//
// It never reads standard input, the arguments or the environment, and there is
// no option to answer in advance, so a process that has no terminal cannot
// answer: Ask refuses with ErrNoTerminal. A bot Parley starts has none (the CLI
// adapter starts it in a session of its own on Linux and macOS, and without a
// console in a job object on Windows).
//
// What this does not stop: a process of the same user that makes itself a
// pseudo-terminal and types the answer on it. The daemon's refusal of callers
// that belong to a bot (internal/botproc) is the second layer for the bots Parley
// starts; for anything else only an operating-system sandbox helps.
package ttyconfirm

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kalahroudi/parley/internal/ttyconfirm/ttydev"
)

// ErrNoTerminal means the process has no controlling terminal, or it could not be opened.
var ErrNoTerminal = errors.New("no terminal to ask on (run this command in a terminal window)")

// maxAnswer bounds the answer read: the question is answered with a word.
const maxAnswer = 16

// terminal opens the controlling terminal; tests replace it.
var terminal = ttydev.Open

// Ask writes prompt to the controlling terminal and reports whether the answer was "y" or "yes" (any case). Anything
// else, including end of input, is a no.
func Ask(prompt string) (bool, error) {
	rw, closeFn, err := terminal()
	if err != nil {
		return false, ErrNoTerminal
	}
	defer closeFn()
	return AskOn(rw, prompt)
}

// AskOn is Ask on a given terminal.
func AskOn(rw io.ReadWriter, prompt string) (bool, error) {
	if _, err := fmt.Fprint(rw, prompt); err != nil {
		return false, ErrNoTerminal
	}
	line, _ := bufio.NewReaderSize(io.LimitReader(rw, maxAnswer), maxAnswer).ReadString('\n') // end of input: line is empty, which is a no
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}
