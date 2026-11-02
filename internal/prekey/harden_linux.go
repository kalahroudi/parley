// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package prekey

import "syscall"

const (
	prSetDumpable = 4  // PR_SET_DUMPABLE
	madvDontDump  = 16 // MADV_DONTDUMP
)

// markUndumpable also stops other same-user processes from ptrace-reading the
// daemon's memory.
func markUndumpable() error { return prctl(prSetDumpable, 0) }

func prctl(option, arg uintptr) error {
	if _, _, e := syscall.Syscall(syscall.SYS_PRCTL, option, arg, 0); e != 0 {
		return e
	}
	return nil
}

// adviseNoDump keeps the key region out of core dumps.
func adviseNoDump(b []byte) error { return syscall.Madvise(b, madvDontDump) }
