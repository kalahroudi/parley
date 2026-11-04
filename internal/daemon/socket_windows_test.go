// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"path/filepath"
	"testing"
)

// Windows sockets carry no peer credentials; the protected DACL on the socket's
// directory is the restriction, and it must hold while the daemon listens.
func TestSocketDirIsPrivate(t *testing.T) {
	ts := startServer(t, nil)
	if err := checkPrivateDir(filepath.Dir(ts.path)); err != nil {
		t.Errorf("socket directory is not private: %v", err)
	}
}
