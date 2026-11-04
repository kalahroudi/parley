// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package localsock

import (
	"errors"
	"net"
)

var errPeer = errors.New("localsock: connection from another user refused")

// checkPeer accepts only connections from processes running as uid want. The
// socket's directory is already private; this is the second, kernel-attested
// check, so a mis-set mode or a bind mount cannot open the daemon to others.
func checkPeer(c net.Conn, want int) error {
	uid, err := peerUID(c)
	if err != nil || int(uid) != want {
		return errPeer
	}
	return nil
}

// peerUID returns the uid of the process that connected.
func peerUID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("localsock: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var cerr error
	read := func(fd uintptr) { uid, cerr = credOf(int(fd)) }
	if err := raw.Control(read); err != nil {
		return 0, err
	}
	return uid, cerr
}
