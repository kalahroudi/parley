// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localsock

import (
	"github.com/kalahroudi/parley/internal/fsperm"
	"path/filepath"
	"testing"
)

// Windows sockets carry no peer credentials; the protected DACL on the socket's
// directory is the restriction, and it must hold while the daemon listens.
func TestSocketDirIsPrivate(t *testing.T) {
	ts := startServer(t, nil)
	if err := fsperm.CheckDir(filepath.Dir(ts.path)); err != nil {
		t.Errorf("socket directory is not private: %v", err)
	}
}

func TestWindowsPeerAndRestrict(t *testing.T) {
	if err := checkPeer(nil, 0); err != nil {
		t.Errorf("checkPeer: %v", err)
	}
	if err := restrict("x"); err != nil {
		t.Errorf("restrict: %v", err)
	}
}
