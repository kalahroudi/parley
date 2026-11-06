// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package acceptance

import "syscall"

// openSockets lists the file descriptors above stderr that are sockets: what a
// bot would hold if the daemon had leaked a connection or its listener to it.
func openSockets() []int {
	var out []int
	for fd := 3; fd < 256; fd++ {
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) == nil && uint32(st.Mode)&syscall.S_IFMT == syscall.S_IFSOCK {
			out = append(out, fd)
		}
	}
	return out
}
