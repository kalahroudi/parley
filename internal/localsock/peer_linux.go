// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package localsock

import "golang.org/x/sys/unix"

// credOf reads the effective uid and the pid of the peer of a connected unix socket (SO_PEERCRED).
func credOf(fd int) (uid uint32, pid int, err error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, 0, err
	}
	return cred.Uid, int(cred.Pid), nil
}
