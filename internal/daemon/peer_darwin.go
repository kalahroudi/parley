// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the effective uid of the process that connected (LOCAL_PEERCRED).
func peerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var x *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { x, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED) }); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return x.Uid, nil
}
