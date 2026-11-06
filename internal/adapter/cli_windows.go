// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package adapter

import (
	"errors"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/kalahroudi/parley/internal/botproc"
)

func prepare(*exec.Cmd) {}

// containTree puts the command in a job object that kills everything in it when terminated or closed (so also if the
// daemon dies), and returns the function that does so. Each step runs even if an earlier one failed (a bad handle
// only makes the next call fail too), and any failure kills the command and the task fails: a bot that cannot be
// contained does not run. (A grandchild started in the instant between the start of the command and its assignment
// to the job is not contained: Go cannot start a process suspended.)
func containTree(cmd *exec.Cmd) (func(), error) {
	job, e1 := windows.CreateJobObject(nil, nil)
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, e2 := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	proc, e3 := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	e4 := windows.AssignProcessToJobObject(job, proc)
	windows.CloseHandle(proc)
	pid := cmd.Process.Pid
	terminate := func() { botproc.UntrackJob(pid); _ = windows.TerminateJobObject(job, 1); windows.CloseHandle(job) }
	if err := errors.Join(e1, e2, e3, e4); err != nil {
		terminate()
		return nil, err
	}
	botproc.TrackJob(pid, job) // the daemon refuses trust-changing commands from anything in this job
	return terminate, nil
}
