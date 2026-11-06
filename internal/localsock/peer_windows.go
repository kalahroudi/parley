// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localsock

import (
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// checkPeer does nothing on Windows: AF_UNIX sockets there carry no peer
// credentials. Access is held to this user by the protected DACL on the socket's
// directory (see fsperm.EnsureDir), which is verified at every start.
func checkPeer(net.Conn, int) error { return nil }

// restrict does nothing on Windows: the directory's DACL is the restriction.
func restrict(string) error { return nil }

// sioAFUnixGetPeerPID is SIO_AF_UNIX_GETPEERPID: the pid of the process at the other end of an AF_UNIX socket.
const sioAFUnixGetPeerPID = 0x58000100

// peerPID returns the pid of the process that connected, as the kernel reports it.
func peerPID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("localsock: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid, n uint32
	var cerr error
	ioctl := func(fd uintptr) {
		cerr = windows.WSAIoctl(windows.Handle(fd), sioAFUnixGetPeerPID, nil, 0, (*byte)(unsafe.Pointer(&pid)), uint32(unsafe.Sizeof(pid)), &n, nil, 0)
	}
	ctl := raw.Control(ioctl) // pid is read after the call: the order of operands in a return is not defined
	return int(pid), errors.Join(ctl, cerr)
}
