// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package prekey

import (
	"math"
	"testing"
)

func TestSysMapLockUnmap(t *testing.T) {
	b, err := sysMap(4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := sysLock(b); err != nil {
		t.Fatalf("this OS must be able to lock a page: %v", err)
	}
	b[0] = 1
	sysUnmap(b)

	if _, err := sysMap(math.MaxInt); err == nil {
		t.Fatal("impossible allocation succeeded")
	}
	// Locking memory that is no longer committed fails and says so.
	if err := sysLock(b); err == nil {
		t.Fatal("locking freed memory succeeded")
	}
}
