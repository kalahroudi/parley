// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package ptytest

import (
	"io"
	"os/exec"
	"strings"
	"testing"
)

func TestStartGivesTheProcessATerminal(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "test -t 0 && test -t 1 && echo terminal")
	master, err := Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	b, _ := io.ReadAll(master) // the read ends with an error when the process has gone; the output is what matters
	if err := cmd.Wait(); err != nil || !strings.Contains(string(b), "terminal") {
		t.Errorf("%v %q", err, b)
	}
}

func TestStartFailsForACommandThatCannotRun(t *testing.T) {
	if master, err := Start(exec.Command("/no/such/command")); err == nil {
		master.Close()
		t.Error("started a command that does not exist")
	}
}
