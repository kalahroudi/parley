// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package toolrun_test

import (
	"net"
	"path/filepath"
	"testing"
)

// listen returns the address of a TCP listener on the loopback that accepts and closes.
func listen(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go accept(ln)
	return ln.Addr().String()
}

// unixListen returns the path of a Unix-domain listener in dir.
func unixListen(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go accept(ln)
	return p
}

func accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
	}
}
