// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package ttyconfirm

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/ptytest"
)

// asksOnATerminal runs the asking child with a pseudo-terminal as its controlling terminal, types typed at it, and returns
// the result it printed.
func asksOnATerminal(t *testing.T, typed string) string {
	t.Helper()
	exe, _ := os.Executable()
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), childEnv+"=1")
	master, err := ptytest.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	done := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(master)
		for sc.Scan() {
			if l := strings.TrimSpace(sc.Text()); strings.HasPrefix(l, "RESULT:") {
				done <- l
				return
			}
		}
		done <- "no result"
	}()
	go func() { time.Sleep(300 * time.Millisecond); master.WriteString(typed) }()
	select {
	case r := <-done:
		cmd.Wait()
		return r
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal("no answer")
		return ""
	}
}

// The person at the terminal can answer, and only an explicit yes counts.
func TestAProcessWithATerminalIsAnsweredOnIt(t *testing.T) {
	if got := asksOnATerminal(t, "yes\n"); got != "RESULT:yes" {
		t.Errorf("typed yes: %q", got)
	}
	if got := asksOnATerminal(t, "no\n"); got != "RESULT:no" {
		t.Errorf("typed no: %q", got)
	}
}
