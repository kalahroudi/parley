// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package localsock

import (
	"net"
	"os"
	"testing"
)

func TestCheckPeerRefusesNonUnixConnections(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := checkPeer(a, 0); err == nil {
		t.Error("a connection with no credentials must be refused")
	}
}

func TestCheckPeerClosedConnection(t *testing.T) {
	ln, err := net.Listen("unix", tempDir(t)+"/p.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err := checkPeer(c, -1); err == nil {
		t.Error("a closed connection must be refused")
	}
}

func TestCredOfBadDescriptor(t *testing.T) {
	if _, err := credOf(-1); err == nil {
		t.Error("a bad descriptor must be an error")
	}
}

func TestPeerUIDOfARealPeer(t *testing.T) {
	ln, err := net.Listen("unix", tempDir(t)+"/p.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if uid, err := peerUID(c); err != nil || int(uid) != os.Geteuid() {
		t.Errorf("peerUID = %d, %v", uid, err)
	}
	if err := checkPeer(c, os.Geteuid()); err != nil {
		t.Errorf("own uid refused: %v", err)
	}
	if err := checkPeer(c, os.Geteuid()+1); err == nil {
		t.Error("another uid accepted")
	}
}

func TestPeerUIDOfAnInvalidConnection(t *testing.T) {
	if _, err := peerUID(&net.UnixConn{}); err == nil {
		t.Error("an invalid connection must be an error")
	}
}
