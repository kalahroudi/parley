// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package prekey

import (
	"runtime"
	"syscall"
	"unsafe"
)

const (
	sigBlock   = 0 // SIG_BLOCK
	sigSetMask = 2 // SIG_SETMASK
)

// quiesce keeps asynchronous signals away from this thread while a private
// scalar is being used, and returns the function that lets them in again.
//
// Why: the kernel writes the interrupted thread's registers (including the
// vector registers, where a 32-byte copy of the scalar sits) onto the thread's
// signal stack, and Go allocates signal stacks in its heap, so a signal that
// lands mid-operation leaves a copy of the key in the heap that nothing ever
// zeroes. The Go runtime sends SIGURG to preempt a running goroutine, which it
// does at the start of every garbage collection: on amd64 CI this put a third
// copy of the second key a test used into the address space about one run in
// three. The thread is locked to this goroutine and the signals are blocked
// (they stay pending, and are delivered when restore runs, after the caller has
// cleared the registers). The runtime copes with a delayed preemption: it
// waits for the next safe point. The operation must therefore be short.
//
// Synchronous faults (SIGSEGV, SIGBUS, SIGFPE, SIGILL) cannot be blocked and
// are not affected. restore must run on the same goroutine.
func quiesce() (restore func()) {
	runtime.LockOSThread()
	// All signals except the synchronous ones; bit n-1 is signal n.
	set := ^uint64(0)
	for _, s := range []syscall.Signal{syscall.SIGSEGV, syscall.SIGBUS, syscall.SIGFPE, syscall.SIGILL} {
		set &^= 1 << (s - 1)
	}
	var old uint64
	if errno := sigprocmask(sigBlock, &set, &old); errno != 0 {
		// Nothing was blocked; the caller still gets a working restore.
		return runtime.UnlockOSThread
	}
	return func() {
		sigprocmask(sigSetMask, &old, nil)
		runtime.UnlockOSThread()
	}
}

// sigprocmask is rt_sigprocmask(2) for this thread (0 on success), a seam for tests.
var sigprocmask = func(how int, set, old *uint64) syscall.Errno {
	_, _, e := syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, uintptr(how), uintptr(unsafe.Pointer(set)), uintptr(unsafe.Pointer(old)), 8, 0, 0)
	return e
}
