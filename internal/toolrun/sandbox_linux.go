// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package toolrun

import (
	"os/exec"
	"path/filepath"
)

// sandbox is bubblewrap (https://github.com/containers/bubblewrap): the file system is read-only except the jail, the
// daemon's directories are replaced by empty ones, the daemon's processes are invisible (new PID namespace) and the network
// is cut unless the tool needs it. The command has no controlling terminal because the adapter starts it in a session of its own.
type sandbox struct {
	bwrap string
	hide  []string
}

// lookPath is exec.LookPath, replaceable by the tests.
var lookPath = exec.LookPath

func findSandbox(hide []string) (boxer, error) {
	p, err := lookPath("bwrap")
	if err != nil || !filepath.IsAbs(p) {
		return nil, ErrNoSandbox
	}
	return sandbox{bwrap: p, hide: existingDirs(hide)}, nil
}

func (b sandbox) wrap(s Spec, args []string, network bool) (string, []string) {
	argv := []string{"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"}
	for _, h := range b.hide {
		argv = append(argv, "--tmpfs", h)
	}
	argv = append(argv, "--bind", s.Dir, s.Dir, "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts")
	if !network {
		argv = append(argv, "--unshare-net")
	}
	argv = append(argv, "--chdir", s.Dir, "--", s.Command)
	return b.bwrap, append(argv, args...)
}
