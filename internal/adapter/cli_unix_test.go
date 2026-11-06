// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package adapter

import (
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// A descriptor the daemon inherited without close-on-exec is marked before a bot is started; one above the stdio
// descriptors and one far up are both covered.
func TestPrepareMarksInheritedDescriptorsCloseOnExec(t *testing.T) {
	low, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0) // the syscall package opens it without close-on-exec
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(low)
	high, err := unix.FcntlInt(uintptr(low), unix.F_DUPFD, maxInheritedFD-1)
	if err != nil {
		t.Skipf("cannot open a descriptor near %d: %v", maxInheritedFD, err) // the soft limit is lower
	}
	defer syscall.Close(high)
	for _, fd := range []int{low, high} {
		if f, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); f&unix.FD_CLOEXEC != 0 {
			t.Fatalf("fd %d starts out close-on-exec, so the test shows nothing", fd)
		}
	}
	cmd := exec.Command("x")
	prepare(cmd)
	for _, fd := range []int{low, high} {
		if f, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); f&unix.FD_CLOEXEC == 0 {
			t.Errorf("fd %d would reach the bot", fd)
		}
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setsid {
		t.Error("the command is not in a session of its own")
	}
}
