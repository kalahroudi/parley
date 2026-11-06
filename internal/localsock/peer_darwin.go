// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package localsock

import "golang.org/x/sys/unix"

// credOf reads the effective uid (LOCAL_PEERCRED) and the pid (LOCAL_PEERPID) of the peer of a connected unix socket.
func credOf(fd int) (uid uint32, pid int, err error) {
	x, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, 0, err
	}
	pid, err = unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		return 0, 0, err
	}
	return x.Uid, pid, nil
}
