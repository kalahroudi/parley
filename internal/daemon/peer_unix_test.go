// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package daemon

import (
	"net"
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
	ln, err := net.Listen("unix", shortTemp(t)+"/p.sock")
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
