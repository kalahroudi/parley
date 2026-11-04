// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package daemon

import (
	"errors"
	"net"
)

var errPeer = errors.New("daemon: connection from another user refused")

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
