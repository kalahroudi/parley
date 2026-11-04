// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package prekey

import (
	"syscall"
	"testing"
)

// SetErrorMode returns the mode that was in force, so setting it to 0 reads back what
// stopErrorReporting set (and 0 puts the process back to the default). The observable effect of
// hardening is that both flags are on: no crash dialog and no Windows Error Reporting dump.
func TestStopErrorReportingSetsBothFlags(t *testing.T) {
	setErrorMode := syscall.NewLazyDLL("kernel32.dll").NewProc("SetErrorMode")
	orig, _, _ := setErrorMode.Call(0) // read the current mode
	t.Cleanup(func() { setErrorMode.Call(orig) })
	setErrorMode.Call(0) // start from nothing set, so a step that sets nothing is seen

	if err := stopErrorReporting(); err != nil {
		t.Fatal(err)
	}
	got, _, _ := setErrorMode.Call(0)
	if got != semFailCriticalErrors|semNoGPFaultErrorBox {
		t.Fatalf("error mode %#x, want %#x (both flags)", got, semFailCriticalErrors|semNoGPFaultErrorBox)
	}
	if semFailCriticalErrors != 0x0001 || semNoGPFaultErrorBox != 0x0002 {
		t.Fatal("the SetErrorMode flag values are fixed by Windows")
	}
}
