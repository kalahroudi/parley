// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package daemon

import (
	"errors"
	"net"
)

// checkPeer refuses everything on platforms Parley does not support, so an
// untested port fails closed instead of running without the peer check.
func checkPeer(net.Conn, int) error { return errors.New("daemon: unsupported platform") }
