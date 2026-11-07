// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package acceptance

// T505: the real parleyd on Windows. A real child process is started in a console and process group of its own (how a
// shell, a scheduled task or a launcher starts it), answers its own user on the local socket, refuses a second
// instance, and stops cleanly on CTRL_BREAK (what Go maps to os.Interrupt; CTRL_CLOSE, logoff and shutdown reach it
// as SIGTERM, which parleyd also handles). After the stop the instance lock is free, the socket answers nothing, and
// the same home starts again.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/localsock"
)

const (
	createNewConsole      = 0x00000010
	createNewProcessGroup = 0x00000200
	ctrlBreakEvent        = 1
	ctrlBreakEnv          = "PARLEY_CTRL_BREAK_PID"
)

var (
	buildOnce sync.Once
	builtExe  string
	buildErr  error
)

// parleydExe builds cmd/parleyd once per test run.
func parleydExe(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "pb")
		if err != nil {
			buildErr = err
			return
		}
		builtExe = filepath.Join(dir, "parleyd.exe")
		out, err := exec.Command("go", "build", "-o", builtExe, "github.com/kalahroudi/parley/cmd/parleyd").CombinedOutput()
		if err != nil {
			buildErr = &buildFailure{err, string(out)}
		}
	})
	if buildErr != nil {
		t.Fatalf("building parleyd: %v", buildErr)
	}
	return builtExe
}

type buildFailure struct {
	err error
	out string
}

func (b *buildFailure) Error() string { return b.err.Error() + ": " + b.out }

// shortHome is a directory with a short path: an AF_UNIX path may not pass 108 characters.
func shortHome(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	root := make([]byte, 32)
	rand.Read(root)
	cfg, _ := json.Marshal(map[string]any{"format": 1, "tenant": "acme", "device_id": "dev1", "gateway_url": "http://127.0.0.1:9",
		"root_public_key": root, "key_store": "file"})
	if err := os.WriteFile(filepath.Join(dir, "config.json"), cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

type runningDaemon struct {
	cmd  *exec.Cmd
	out  *bytes.Buffer
	done chan error
	home string
}

// startParleyd starts the real daemon in its own console and process group.
func startParleyd(t *testing.T, home string) *runningDaemon {
	t.Helper()
	d := &runningDaemon{out: &bytes.Buffer{}, done: make(chan error, 1), home: home}
	d.cmd = exec.Command(parleydExe(t))
	d.cmd.Env = append(os.Environ(), "PARLEY_HOME="+home)
	d.cmd.Stdout, d.cmd.Stderr = d.out, d.out
	d.cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewConsole | createNewProcessGroup, HideWindow: true}
	if err := d.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { d.done <- d.cmd.Wait() }()
	t.Cleanup(func() { d.cmd.Process.Kill() })
	return d
}

func (d *runningDaemon) answers() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := localsock.Call(ctx, filepath.Join(d.home, "parleyd.sock"), "status", nil)
	return err == nil && r.OK
}

func (d *runningDaemon) waitUp(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		select {
		case err := <-d.done:
			t.Fatalf("parleyd exited before it answered: %v\n%s", err, d.out.String())
		default:
		}
		if d.answers() {
			return
		}
	}
	t.Fatalf("parleyd did not answer on its socket in 60 s\n%s", d.out.String())
}

// ctrlBreak sends CTRL_BREAK to the daemon's process group from a helper process: attaching to another console and
// raising the event would otherwise change this test process's own console.
func ctrlBreak(t *testing.T, pid int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCtrlBreakHelper$")
	cmd.Env = append(os.Environ(), ctrlBreakEnv+"="+strconv.Itoa(pid))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("CTRL_BREAK helper: %v\n%s", err, out)
	}
}

// TestCtrlBreakHelper is the helper process of ctrlBreak; it does nothing in a normal run.
func TestCtrlBreakHelper(t *testing.T) {
	v := os.Getenv(ctrlBreakEnv)
	if v == "" {
		t.Skip("helper process")
	}
	pid, _ := strconv.Atoi(v)
	k := syscall.NewLazyDLL("kernel32.dll")
	k.NewProc("FreeConsole").Call()
	if r, _, err := k.NewProc("AttachConsole").Call(uintptr(pid)); r == 0 {
		t.Fatalf("AttachConsole(%d): %v", pid, err)
	}
	k.NewProc("SetConsoleCtrlHandler").Call(0, 1) // this process ignores the event it raises
	if r, _, err := k.NewProc("GenerateConsoleCtrlEvent").Call(ctrlBreakEvent, uintptr(pid)); r == 0 {
		t.Fatalf("GenerateConsoleCtrlEvent: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
}

func TestWindowsDaemonLifecycle(t *testing.T) {
	home := shortHome(t)
	for round := 1; round <= 2; round++ { // the second round is a restart on the state the first left
		d := startParleyd(t, home)
		d.waitUp(t)

		// One instance per home: a second start is refused and the first is untouched.
		second := exec.Command(parleydExe(t))
		second.Env = append(os.Environ(), "PARLEY_HOME="+home)
		out, err := second.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "already running") {
			t.Fatalf("round %d: a second parleyd was not refused: %v\n%s", round, err, out)
		}
		if !d.answers() {
			t.Fatalf("round %d: the first daemon stopped answering after a second start was refused", round)
		}

		ctrlBreak(t, d.cmd.Process.Pid)
		select {
		case err := <-d.done:
			if err != nil {
				t.Fatalf("round %d: parleyd did not exit 0 on CTRL_BREAK: %v\n%s", round, err, d.out.String())
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("round %d: parleyd did not stop within 30 s of CTRL_BREAK\n%s", round, d.out.String())
		}
		if !strings.Contains(d.out.String(), "parleyd stopped") {
			t.Errorf("round %d: no ordered shutdown in the log:\n%s", round, d.out.String())
		}
		if d.answers() {
			t.Errorf("round %d: the socket still answers after the daemon stopped", round)
		}
		release, err := daemon.LockState(home)
		if err != nil {
			t.Fatalf("round %d: the instance lock is still held after the stop: %v", round, err)
		}
		release()
	}
}
