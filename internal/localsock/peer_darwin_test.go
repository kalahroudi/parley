// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package localsock

import (
	"net"
	"testing"
)

// LOCAL_PEERCRED still answers after the peer has gone, LOCAL_PEERPID does not: the pid read must fail closed.
// This is deterministic (the client's close is done before the read), unlike a hostile client racing the server.
func TestCredOfPeerGoneAfterAccept(t *testing.T) {
	ln, err := net.Listen("unix", tempDir(t)+"/g.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c.Close()
	raw, err := s.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cerr error
	if err := raw.Control(func(fd uintptr) { _, _, cerr = credOf(int(fd)) }); err != nil {
		t.Fatal(err)
	}
	if cerr == nil {
		t.Fatal("the pid of a peer that has closed was still reported")
	}
}
