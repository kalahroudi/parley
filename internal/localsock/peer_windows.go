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

var errPeer = errors.New("localsock: connection from another user refused")

// Seams for tests: the Win32 calls that cannot be made to fail (or to report a
// stranger) on a healthy machine.
var (
	ownSIDFn  = func() (*windows.SID, error) { return tokenSID(windows.GetCurrentProcessToken()) }
	peerSIDFn = peerSID

	openProcessToken = windows.OpenProcessToken
)

// checkPeer accepts only connections from processes whose token belongs to the
// daemon's own user. AF_UNIX on Windows carries no peer credentials, but the
// kernel reports the pid of the connecting process (SIO_AF_UNIX_GETPEERPID), so
// the check opens that process, reads its token's user SID and compares it with
// ours. Anything that cannot be read is refused. The uid argument is the Unix
// check's and is unused here.
//
// This is the second check after the directory's protected DACL, and it is
// weaker than the Unix one in one way: the pid is looked up after the connection
// is accepted, so a peer that exits and whose pid is reused by another process
// before the lookup is judged as that process. The directory DACL still keeps
// other users from connecting at all.
func checkPeer(c net.Conn, _ int) error {
	want, err := ownSIDFn()
	if err != nil {
		return errPeer
	}
	pid, err := peerPIDFn(c)
	if err != nil || pid <= 0 {
		return errPeer
	}
	got, err := peerSIDFn(uint32(pid))
	if err != nil || !got.Equals(want) {
		return errPeer
	}
	return nil
}

// peerSID returns the user SID of the process with the given pid.
func peerSID(pid uint32) (*windows.SID, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := openProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return nil, err
	}
	defer tok.Close()
	return tokenSID(tok)
}

func tokenSID(t windows.Token) (*windows.SID, error) {
	u, err := t.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}

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
