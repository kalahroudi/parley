// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"runtime"
	"strings"
	"testing"
)

func skipWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no pseudo-terminal on Windows")
	}
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errw strings.Builder
	code := serve(args, &out, &errw)
	return code, out.String(), errw.String()
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"-nope", "--", "x"}, {"-timeout", "1s"}} {
		if code, _, errw := run(t, args...); code != 2 || !strings.Contains(errw, "usage") {
			t.Fatalf("%v: code %d, %q", args, code, errw)
		}
	}
}

func TestWindowsReportsNoTerminal(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("only Windows has no pseudo-terminal")
	}
	if code, _, errw := run(t, "cmd"); code != 125 || errw == "" {
		t.Fatalf("code %d, %q", code, errw)
	}
}

func TestTypesTheAnswerAfterThePrompt(t *testing.T) {
	skipWindows(t)
	code, out, _ := run(t, "-after", "name?", "-type", "yes", "--", "sh", "-c", `printf 'name? '; read a; echo "got:$a"; [ -t 0 ] && echo tty`)
	if code != 0 || !strings.Contains(out, "got:yes") || !strings.Contains(out, "tty") {
		t.Fatalf("code %d, output %q", code, out)
	}
}

func TestPassesOnTheExitCode(t *testing.T) {
	skipWindows(t)
	if code, _, _ := run(t, "--", "sh", "-c", "exit 3"); code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
}

func TestACommandThatDoesNotStart(t *testing.T) {
	skipWindows(t)
	if code, _, errw := run(t, "--", "/nonexistent/command"); code != 125 || errw == "" {
		t.Fatalf("code %d, %q", code, errw)
	}
}

func TestKillsACommandThatOutlivesTheTimeout(t *testing.T) {
	skipWindows(t)
	if code, _, _ := run(t, "-timeout", "300ms", "--", "sleep", "30"); code == 0 {
		t.Fatal("a command that was killed reported success")
	}
}
