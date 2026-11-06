// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package toolrun

import (
	"os"
	"strconv"
	"strings"
)

// sandboxExec is where macOS keeps sandbox-exec. Apple marks it deprecated but still ships and enforces it.
var sandboxExec = "/usr/bin/sandbox-exec"

// sandbox is a sandbox-exec profile: nothing is written outside the jail, the daemon's directories cannot be read, no
// connection to or from a Unix-domain socket, and no network at all unless the tool needs it.
type sandbox struct{ hide []string }

func findSandbox(hide []string) (boxer, error) {
	if fi, err := os.Stat(sandboxExec); err != nil || fi.IsDir() {
		return nil, ErrNoSandbox
	}
	return sandbox{hide: existingDirs(hide)}, nil
}

func (b sandbox) wrap(s Spec, args []string, network bool) (string, []string) {
	var p strings.Builder
	p.WriteString("(version 1)\n(allow default)\n")
	p.WriteString("(deny file-write*)\n(allow file-write* (subpath (param \"JAIL\")) (literal \"/dev/null\"))\n")
	argv := []string{"-D", "JAIL=" + s.Dir}
	for i, h := range b.hide {
		name := "HIDE" + strconv.Itoa(i)
		p.WriteString("(deny file-read* file-write* (subpath (param \"" + name + "\")))\n")
		argv = append(argv, "-D", name+"="+h)
	}
	p.WriteString("(deny network-outbound (remote unix-socket))\n(deny network-bind (local unix-socket))\n")
	if !network {
		p.WriteString("(deny network*)\n")
	}
	argv = append(argv, "-p", p.String(), s.Command)
	return sandboxExec, append(argv, args...)
}
