// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package botproc

import (
	"bytes"
	"os"
	"strconv"
)

// procRoot is replaced by tests.
var procRoot = "/proc"

// lookup reads /proc/<pid>/stat: "pid (comm) state ppid pgrp session ...". comm may hold spaces and parentheses, so
// the fields are counted from the last ')'.
func lookup(pid int) (info, error) {
	b, err := os.ReadFile(procRoot + "/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return info{}, err
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return info{}, ErrUnknown
	}
	f := bytes.Fields(b[i+1:])
	if len(f) < 4 {
		return info{}, ErrUnknown
	}
	var out [3]int
	for k := range out {
		n, err := strconv.Atoi(string(f[k+1]))
		if err != nil {
			return info{}, ErrUnknown
		}
		out[k] = n
	}
	return info{ppid: out[0], groups: []int{out[1], out[2]}}, nil
}
