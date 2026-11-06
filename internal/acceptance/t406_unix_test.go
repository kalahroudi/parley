// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package acceptance

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/ptytest"
	"github.com/kalahroudi/parley/internal/ttyconfirm"
)

// openSockets lists the file descriptors above stderr that are sockets: what a
// bot would hold if the daemon had leaked a connection or its listener to it.
func openSockets() []int {
	var out []int
	for fd := 3; fd < 256; fd++ {
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) == nil && uint32(st.Mode)&syscall.S_IFMT == syscall.S_IFSOCK {
			out = append(out, fd)
		}
	}
	return out
}

// A descriptor the daemon inherited from whatever started it (not close-on-exec) must not reach a bot.
func TestBotDoesNotInheritALeakedSocket(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0) // the syscall package opens it without close-on-exec
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := t406CLI(t, "probe", t.TempDir()).Handle(ctx, t406Task, &countSession{})
	if err != nil {
		t.Fatal(err)
	}
	var rep probeReport
	if err := json.Unmarshal(res, &rep); err != nil {
		t.Fatalf("%q: %v", res, err)
	}
	if len(rep.Sockets) != 0 {
		t.Errorf("the bot inherited the leaked socket %d: %v", fd, rep.Sockets)
	}
}

func ownGroup(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// A daemon that has a controlling terminal (the owner started it in a window) does not pass it on: the bot the adapter
// starts has none, so it cannot ask the owner's terminal, and a "yes" typed at that terminal is not read by the bot.
// Without the new session the bot inherits the terminal and answers from it, and this fails.
func TestBotOfADaemonWithATerminalHasNone(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report")
	host := exec.Command(exe)
	host.Env = append(os.Environ(), t406Env+"=host", "PARLEY_T406_OUT="+out)
	master, err := ptytest.Start(host)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	go io.Copy(io.Discard, master) // the terminal's output
	go func() {
		for i := 0; i < 40; i++ { // type the answer a bot would need, over and over while the bot lives
			time.Sleep(250 * time.Millisecond)
			if _, err := master.WriteString("yes\n"); err != nil {
				return
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- host.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the host failed: %v", err)
		}
	case <-time.After(60 * time.Second):
		host.Process.Kill()
		t.Fatal("the host never finished")
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep hostReport
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatalf("%q: %v", b, err)
	}
	if !rep.HostHasTerminal {
		t.Fatal("the host has no terminal, so the test shows nothing")
	}
	if rep.Failed || rep.Bot != "error: "+ttyconfirm.ErrNoTerminal.Error() {
		t.Errorf("the bot of a daemon with a terminal: %+v", rep)
	}
}
