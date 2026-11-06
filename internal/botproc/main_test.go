// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package botproc

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

const modeEnv = "PARLEY_BOTPROC_MODE"

// TestMain lets the test binary play the processes a bot is made of.
//
//	noop    exits at once
//	sleep   waits
//
// The next three wait for a line on standard input first, so that the test can put the process where it belongs
// (a job object on Windows) before it starts anything:
//
//	spawn   starts a "sleep" child, prints its pid, then waits
//	orphan  starts a "sleep" child, prints its pid and exits, leaving the child without its parent
//	escape  starts a child that leaves the session and process group, prints its pid and exits
//	leave   (the child of escape) leaves the session, then waits
func TestMain(m *testing.M) {
	switch os.Getenv(modeEnv) {
	case "":
		os.Exit(m.Run())
	case "sleep":
		time.Sleep(time.Minute)
	case "spawn", "orphan":
		waitForGo()
		fmt.Println(child("sleep"))
		if os.Getenv(modeEnv) == "spawn" {
			time.Sleep(time.Minute)
		}
	case "escape":
		waitForGo()
		fmt.Println(child("leave"))
	case "leave":
		leaveSession()
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}

// child starts this binary in the given mode, in the same session and process group, and returns its pid.
func child(mode string) int {
	exe, _ := os.Executable()
	c := exec.Command(exe)
	c.Env = append(os.Environ(), modeEnv+"="+mode)
	if err := c.Start(); err != nil {
		panic(err)
	}
	return c.Process.Pid
}

func waitForGo() { bufio.NewReader(os.Stdin).ReadString('\n') }
