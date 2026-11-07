// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package adapter

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A path the agent asked for that has become a named pipe is not opened for good: reading it fails at once (it is not a
// regular file) and so does writing it (no reader), instead of blocking the task.
func TestNamedPipesDoNotBlockTheTask(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "p"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan [2]*rpcError, 1)
	go func() {
		_, r := readFile(dir, "p", nil, nil)
		done <- [2]*rpcError{r, writeFile(dir, "p", "x")}
	}()
	select {
	case got := <-done:
		if got[0] != errFile || got[1] != errFile {
			t.Fatalf("%v %v", got[0], got[1])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the task blocked on a named pipe")
	}
}
