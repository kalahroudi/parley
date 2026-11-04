// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localsock

import "net"

// checkPeer does nothing on Windows: AF_UNIX sockets there carry no peer
// credentials. Access is held to this user by the protected DACL on the socket's
// directory (see fsperm.EnsureDir), which is verified at every start.
func checkPeer(net.Conn, int) error { return nil }

// restrict does nothing on Windows: the directory's DACL is the restriction.
func restrict(string) error { return nil }
