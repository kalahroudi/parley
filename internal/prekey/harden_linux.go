// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package prekey

import "syscall"

const prSetDumpable = 4 // PR_SET_DUMPABLE

// markUndumpable also stops other same-user processes from ptrace-reading the
// daemon's memory.
func markUndumpable() error {
	if _, _, e := syscall.Syscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); e != 0 {
		return e
	}
	return nil
}
