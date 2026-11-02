// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package prekey

import (
	"syscall"
	"testing"
)

func TestPrctlAndMadvise(t *testing.T) {
	if err := prctl(0x7fffffff, 0); err == nil {
		t.Fatal("invalid prctl option accepted")
	}
	if err := markUndumpable(); err != nil {
		t.Fatal(err)
	}
	b, err := sysMap(4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := adviseNoDump(b); err != nil {
		t.Fatal(err)
	}
	syscall.Munmap(b)
	if err := adviseNoDump(b); err == nil {
		t.Fatal("advice on unmapped memory accepted")
	}
}
