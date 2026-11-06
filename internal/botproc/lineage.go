// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package botproc

// info is what the kernel says about a process's place in the tree: its parent, and the ids of the process group and
// (where the system gives it) the session it is in.
type info struct {
	ppid   int
	groups []int
}

// owns walks pid and its parents. roots holds the pid of each running bot, which is also the id of the session or
// process group it was started in.
// lookupFn is lookup, replaceable so that the walk can be tested on trees no real process list gives (very deep, cyclic).
var lookupFn = lookup

func owns(roots map[int]int, pid int) (bool, error) {
	for depth := 0; depth < maxDepth && pid > 1; depth++ {
		if _, ok := roots[pid]; ok {
			return true, nil
		}
		in, err := lookupFn(pid)
		if err != nil {
			return false, ErrUnknown
		}
		for _, g := range in.groups {
			if _, ok := roots[g]; ok {
				return true, nil
			}
		}
		pid = in.ppid
	}
	return false, nil
}
