// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package localsock

import "golang.org/x/sys/unix"

// credOf reads the effective uid of the peer of a connected unix socket (SO_PEERCRED).
func credOf(fd int) (uint32, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}
