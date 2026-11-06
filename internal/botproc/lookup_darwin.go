// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package botproc

import "golang.org/x/sys/unix"

// kinfoProc is replaced by tests: the system call cannot be made to fail on a healthy machine.
var kinfoProc = unix.SysctlKinfoProc

// lookup reads the process's entry in the kernel's process table. macOS does not give another session's id to an
// unprivileged process, so only the process group (a new one per bot, see the adapter) stands in for it.
func lookup(pid int) (info, error) {
	k, err := kinfoProc("kern.proc.pid", pid)
	if err != nil {
		return info{}, err
	}
	if int(k.Proc.P_pid) != pid { // an empty answer: no such process
		return info{}, ErrUnknown
	}
	return info{ppid: int(k.Eproc.Ppid), groups: []int{int(k.Eproc.Pgid)}}, nil
}
