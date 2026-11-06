// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package botproc

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func leaveSession() { syscall.Setsid() }

// startBot starts this binary in the given mode as the CLI adapter starts a bot (a session of its own), registers it, and
// returns its pid and the pid it printed (0 if none), with the registry. The bot is killed and reaped at the end.
func startBot(t *testing.T, mode string) (r *Registry, pid, printed int) {
	t.Helper()
	exe, _ := os.Executable()
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), modeEnv+"="+mode)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, _ := cmd.StdoutPipe()
	in, _ := cmd.StdinPipe()
	r = &Registry{}
	remove, err := r.Launch(func() (int, error) { return cmd.Process.Pid, cmd.Start() })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		cmd.Wait()
		remove()
	})
	if mode != "sleep" {
		in.Write([]byte("go\n"))
		line, _ := bufio.NewReader(out).ReadString('\n')
		printed, _ = strconv.Atoi(strings.TrimSpace(line))
		if printed == 0 {
			t.Fatalf("the %s process printed %q", mode, line)
		}
		t.Cleanup(func() { syscall.Kill(printed, syscall.SIGKILL) })
	}
	return r, cmd.Process.Pid, printed
}

func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), modeEnv+"=noop")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return cmd.Process.Pid
}

func TestTheBotAndItsDescendantsBelongToIt(t *testing.T) {
	r, bot, child := startBot(t, "spawn")
	for name, pid := range map[string]int{"the bot": bot, "its child": child} {
		if own, err := r.Owns(pid); !own || err != nil {
			t.Errorf("%s (%d): %v %v", name, pid, own, err)
		}
	}
	if own, err := r.Owns(os.Getpid()); own || err != nil {
		t.Errorf("this process, which started no bot here, is taken for one: %v %v", own, err)
	}
	if own, err := r.Owns(os.Getppid()); own || err != nil {
		t.Errorf("this process's parent is taken for a bot: %v %v", own, err)
	}
}

// A child whose parent has gone is still in the bot's session (Linux) or process group (macOS).
func TestAnOrphanedDescendantStillBelongsToTheBot(t *testing.T) {
	r, _, orphan := startBot(t, "orphan")
	deadline := time.Now().Add(10 * time.Second)
	for {
		in, err := lookup(orphan)
		if err == nil && in.ppid != orphan && !isBot(r, in.ppid) { // reparented: its parent is not the bot's process any more
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the child was never orphaned")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if own, err := r.Owns(orphan); !own || err != nil {
		t.Errorf("an orphan of the bot: %v %v", own, err)
	}
}

func isBot(r *Registry, pid int) bool { _, ok := r.pids[pid]; return ok }

// The known limit, stated as a test: a descendant that leaves the session and the process group and loses its parent is
// not recognised. Only an operating-system sandbox covers it (see the README).
func TestKnownLimitADescendantThatLeavesTheSessionIsNotRecognised(t *testing.T) {
	r, bot, escaped := startBot(t, "escape")
	deadline := time.Now().Add(10 * time.Second)
	for {
		in, err := lookup(escaped)
		if err == nil && in.groups[0] == escaped && in.ppid != bot { // setsid made it the leader of a new session and group, and its parent has gone
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the child never left the session and lost its parent")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if own, err := r.Owns(escaped); own || err != nil {
		t.Errorf("the documented limit changed (an escaped descendant used to go unrecognised): %v %v", own, err)
	}
}

func TestAProcessThatHasGoneCannotBeJudgedWhileABotRuns(t *testing.T) {
	r, _, _ := startBot(t, "sleep")
	if _, err := r.Owns(deadPID(t)); !errors.Is(err, ErrUnknown) {
		t.Errorf("%v", err)
	}
}

// The walk up a process's parents stops, whatever the tree.
func TestOwnsWalkIsBounded(t *testing.T) {
	roots := map[int]int{999999: 1}
	if own, err := owns(roots, os.Getpid()); own || err != nil {
		t.Errorf("%v %v", own, err)
	}
	if own, err := owns(roots, 1); own || err != nil {
		t.Errorf("init: %v %v", own, err)
	}
	if own, err := owns(roots, 0); own || err != nil {
		t.Errorf("pid 0: %v %v", own, err)
	}
}
