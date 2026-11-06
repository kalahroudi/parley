// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package botproc

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// jobs are the job objects bots run in, by the bot's pid. The adapter tracks a job when it creates it and untracks it
// before closing the handle.
var (
	jobsMu sync.Mutex
	jobs   = map[int]windows.Handle{}
)

var procIsProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

// TrackJob records the job object a bot was assigned to.
func TrackJob(pid int, job windows.Handle) {
	jobsMu.Lock()
	jobs[pid] = job
	jobsMu.Unlock()
}

// UntrackJob forgets the job; call it before the handle is closed.
func UntrackJob(pid int) {
	jobsMu.Lock()
	delete(jobs, pid)
	jobsMu.Unlock()
}

// owns asks the system whether the process is in one of the bots' jobs. A job cannot be left by a descendant (the
// adapter sets no breakaway), whatever happens to the parent.
func owns(roots map[int]int, pid int) (bool, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false, ErrUnknown
	}
	defer windows.CloseHandle(h)
	jobsMu.Lock()
	defer jobsMu.Unlock()
	for root := range roots {
		job, ok := jobs[root]
		if !ok {
			return false, ErrUnknown // a bot without a job cannot be told apart: refuse
		}
		var in int32
		if r, _, _ := procIsProcessInJob.Call(uintptr(h), uintptr(job), uintptr(unsafe.Pointer(&in))); r == 0 {
			return false, ErrUnknown
		}
		if in != 0 {
			return true, nil
		}
	}
	return false, nil
}

// lookup is only used to tell that a process exists.
func lookup(pid int) (info, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return info{}, err
	}
	windows.CloseHandle(h)
	return info{}, nil
}

type info struct{}
