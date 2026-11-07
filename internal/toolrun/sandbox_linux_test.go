// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package toolrun

import (
	"errors"
	"os/exec"
	"reflect"
	"testing"
)

func TestWithoutBubblewrapNoToolRuns(t *testing.T) {
	old := lookPath
	defer func() { lookPath = old }()
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	if _, err := New(Config{}); !errors.Is(err, ErrNoSandbox) {
		t.Fatalf("missing: %v", err)
	}
	lookPath = func(string) (string, error) { return "bwrap", nil } // found relative to the working directory: not trusted
	if _, err := New(Config{}); !errors.Is(err, ErrNoSandbox) {
		t.Fatalf("relative: %v", err)
	}
}

func TestBubblewrapArgumentsConfineTheTool(t *testing.T) {
	jail, hide := t.TempDir(), t.TempDir()
	old := lookPath
	defer func() { lookPath = old }()
	lookPath = func(string) (string, error) { return "/usr/bin/bwrap", nil }
	bx, err := findSandbox([]string{hide, "/nonexistent/dir"})
	if err != nil {
		t.Fatal(err)
	}
	b := bx.(sandbox)
	s := Spec{Command: "/bin/tool", Dir: jail}
	path, argv := b.wrap(s, []string{"x", "y"}, false)
	want := []string{"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", b.hide[0], "--bind", jail, jail,
		"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net", "--chdir", jail, "--", "/bin/tool", "x", "y"}
	if path != "/usr/bin/bwrap" || !reflect.DeepEqual(argv, want) || len(b.hide) != 1 {
		t.Fatalf("%s %q\nwant %q", path, argv, want)
	}
	_, argv = b.wrap(s, nil, true) // the network is declared: it is shared
	for _, a := range argv {
		if a == "--unshare-net" {
			t.Fatal("the network was cut for a tool that needs it")
		}
	}
}
