// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package toolrun

import (
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestWithoutSandboxExecNoToolRuns(t *testing.T) {
	old := sandboxExec
	defer func() { sandboxExec = old }()
	for _, p := range []string{"/nonexistent/sandbox-exec", os.TempDir()} { // missing, and a directory
		sandboxExec = p
		if _, err := New(Config{}); !errors.Is(err, ErrNoSandbox) {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func TestProfileDeniesWritesOutsideTheJailSocketsAndHiddenDirectories(t *testing.T) {
	jail, hide := t.TempDir(), t.TempDir()
	bx, _ := findSandbox([]string{hide, "/nonexistent/dir"})
	b := bx.(sandbox)
	s := Spec{Command: "/bin/tool", Dir: jail}
	path, argv := b.wrap(s, []string{"x", "y"}, false)
	profile := "(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write* (subpath (param \"JAIL\")) (literal \"/dev/null\"))\n" +
		"(deny file-read* file-write* (subpath (param \"HIDE0\")))\n" +
		"(deny network-outbound (remote unix-socket))\n(deny network-bind (local unix-socket))\n(deny network*)\n"
	want := []string{"-D", "JAIL=" + jail, "-D", "HIDE0=" + b.hide[0], "-p", profile, "/bin/tool", "x", "y"}
	if path != sandboxExec || !reflect.DeepEqual(argv, want) || len(b.hide) != 1 {
		t.Fatalf("%s %q\nwant %q", path, argv, want)
	}
	_, argv = b.wrap(s, nil, true) // the network is declared: only the Unix-domain rules remain
	if p := argv[len(argv)-2]; p != profile[:len(profile)-len("(deny network*)\n")] {
		t.Fatalf("with the network: %q", p)
	}
}
