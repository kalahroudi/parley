// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package botproc

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func leaveSession() {}

func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), modeEnv+"=noop")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	// The process object lives on while any handle to it is open (the system's own, a scanner's); wait until it is gone.
	for i := 0; i < 500; i++ {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
		if err != nil {
			return cmd.Process.Pid
		}
		windows.CloseHandle(h)
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the process object of an exited process never went away")
	return 0
}

// startBot starts this binary in the given mode as the CLI adapter starts a bot (assigned to a job object that is
// tracked), registers it in r, and returns its pid and the pid it printed (0 if none). The job is killed at the end.
func startBot(t *testing.T, r *Registry, mode string) (pid, printed int) {
	t.Helper()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), modeEnv+"="+mode)
	out, _ := cmd.StdoutPipe()
	in, _ := cmd.StdinPipe()
	remove, err := r.Launch(func() (int, error) { return cmd.Process.Pid, cmd.Start() })
	if err != nil {
		t.Fatal(err)
	}
	pid = cmd.Process.Pid
	t.Cleanup(func() {
		UntrackJob(pid)
		windows.TerminateJobObject(job, 1)
		windows.CloseHandle(job)
		cmd.Wait()
		remove()
	})
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		t.Fatal(err)
	}
	err = windows.AssignProcessToJobObject(job, proc)
	windows.CloseHandle(proc)
	if err != nil {
		t.Fatal(err)
	}
	TrackJob(pid, job)
	if mode != "sleep" {
		in.Write([]byte("go\n"))
		line, _ := bufio.NewReader(out).ReadString('\n')
		printed, _ = strconv.Atoi(strings.TrimSpace(line))
		if printed == 0 {
			t.Fatalf("the %s process printed %q", mode, line)
		}
	}
	return pid, printed
}

func TestTheBotAndItsDescendantsAreInItsJob(t *testing.T) {
	r := &Registry{}
	bot, child := startBot(t, r, "spawn")
	for name, pid := range map[string]int{"the bot": bot, "its child": child} {
		if own, err := r.Owns(pid); !own || err != nil {
			t.Errorf("%s (%d): %v %v", name, pid, own, err)
		}
	}
	if own, err := r.Owns(os.Getpid()); own || err != nil {
		t.Errorf("this process is taken for a bot: %v %v", own, err)
	}
}

func TestEachOfSeveralBotsIsRecognised(t *testing.T) {
	r := &Registry{}
	first, _ := startBot(t, r, "sleep")
	second, _ := startBot(t, r, "sleep")
	for _, pid := range []int{first, second} {
		if own, err := r.Owns(pid); !own || err != nil {
			t.Errorf("%d: %v %v", pid, own, err)
		}
	}
}

func TestAProcessThatHasGoneCannotBeJudged(t *testing.T) {
	r := &Registry{}
	startBot(t, r, "sleep")
	if _, err := r.Owns(deadPID(t)); !errors.Is(err, ErrUnknown) {
		t.Errorf("%v", err)
	}
}

// A bot whose job is not known cannot be told apart from anything, so every question is refused.
func TestABotWithoutAJobRefusesEveryQuestion(t *testing.T) {
	r := &Registry{}
	pid, _ := startBot(t, r, "sleep")
	UntrackJob(pid)
	if _, err := r.Owns(os.Getpid()); !errors.Is(err, ErrUnknown) {
		t.Errorf("%v", err)
	}
}

func TestAJobThatCannotBeQueriedRefusesEveryQuestion(t *testing.T) {
	r := &Registry{}
	pid, _ := startBot(t, r, "sleep")
	TrackJob(pid, windows.Handle(0xdeadbeef)) // not a handle of this process
	if _, err := r.Owns(os.Getpid()); !errors.Is(err, ErrUnknown) {
		t.Errorf("%v", err)
	}
}
