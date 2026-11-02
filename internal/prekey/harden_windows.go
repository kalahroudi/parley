// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package prekey

import "syscall"

const (
	semFailCriticalErrors = 0x0001
	semNoGPFaultErrorBox  = 0x0002
)

// disableCoreDumps stops Windows Error Reporting from writing a crash dump.
func disableCoreDumps() error {
	p := syscall.NewLazyDLL("kernel32.dll").NewProc("SetErrorMode")
	p.Call(semFailCriticalErrors | semNoGPFaultErrorBox)
	return nil
}
