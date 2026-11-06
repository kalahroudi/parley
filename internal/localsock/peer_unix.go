// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package localsock

import (
	"errors"
	"net"
)

var errPeer = errors.New("localsock: connection from another user refused")

// There is deliberately no implementation for other platforms: the package does
// not build there, so an untested port cannot run without the peer check.

// checkPeer accepts only connections from processes running as uid want. The
// socket's directory is already private; this is the second, kernel-attested
// check, so a mis-set mode or a bind mount cannot open the daemon to others.
func checkPeer(c net.Conn, want int) error {
	uid, _, err := peerCred(c)
	if err != nil || int(uid) != want {
		return errPeer
	}
	return nil
}

// peerPID returns the pid of the process that connected, as the kernel reports it.
func peerPID(c net.Conn) (int, error) {
	_, pid, err := peerCred(c)
	return pid, err
}

// peerCred returns the uid and pid of the process that connected.
func peerCred(c net.Conn) (uid uint32, pid int, err error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("localsock: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cerr error
	read := func(fd uintptr) { uid, pid, cerr = credOf(int(fd)) }
	if err := raw.Control(read); err != nil {
		return 0, 0, err
	}
	return uid, pid, cerr
}
