// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localsock

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kalahroudi/parley/internal/fsperm"
	"golang.org/x/sys/windows"
)

// Windows sockets carry no peer credentials; the protected DACL on the socket's
// directory is the restriction, and it must hold while the daemon listens.
func TestSocketDirIsPrivate(t *testing.T) {
	ts := startServer(t, nil)
	if err := fsperm.CheckDir(filepath.Dir(ts.path)); err != nil {
		t.Errorf("socket directory is not private: %v", err)
	}
}

func TestWindowsRestrictIsDirectoryDACL(t *testing.T) {
	if err := restrict("x"); err != nil {
		t.Errorf("restrict: %v", err)
	}
}

var okMethod = map[string]Method{"x": func(context.Context, json.RawMessage) (any, error) { return 1, nil }}

// The same user is served: the real token lookup of the real peer pid.
func TestWindowsPeerSameUserServed(t *testing.T) {
	ts := startServer(t, okMethod)
	if r, err := Call(context.Background(), ts.path, "x", nil); err != nil || !r.OK {
		t.Fatalf("own user must be served: %+v %v", r, err)
	}
}

func TestWindowsPeerOtherUserRefused(t *testing.T) {
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	old := peerSIDFn
	peerSIDFn = func(uint32) (*windows.SID, error) { return everyone, nil } // a peer running as another user
	t.Cleanup(func() { peerSIDFn = old })
	ts := startServer(t, okMethod)
	if r, err := Call(context.Background(), ts.path, "x", nil); err == nil && r.OK {
		t.Fatal("a connection from another user was served")
	}
	waitFor(t, "refusal logged", func() bool { return strings.Contains(ts.log.String(), "not this user") })
}

// Everything that cannot be read is refused, never served.
func TestWindowsPeerFailsClosed(t *testing.T) {
	boom := errors.New("boom")
	own, _ := windows.CreateWellKnownSid(windows.WinWorldSid)
	oldOwn, oldPeer := ownSIDFn, peerSIDFn
	t.Cleanup(func() { ownSIDFn, peerSIDFn = oldOwn, oldPeer })
	srv, cli := net.Pipe() // not a unix connection: no pid can be read
	defer srv.Close()
	defer cli.Close()
	ownSIDFn = func() (*windows.SID, error) { return own, nil }
	peerSIDFn = func(uint32) (*windows.SID, error) { return own, nil }
	if err := checkPeer(srv, 0); err == nil {
		t.Error("a connection without a readable pid was accepted")
	}
	ownSIDFn = func() (*windows.SID, error) { return nil, boom }
	if err := checkPeer(srv, 0); err == nil {
		t.Error("an unreadable own token was accepted")
	}
	ownSIDFn = oldOwn
	peerSIDFn = func(uint32) (*windows.SID, error) { return nil, boom }
	ts := startServer(t, okMethod)
	if r, err := Call(context.Background(), ts.path, "x", nil); err == nil && r.OK {
		t.Fatal("a peer whose token cannot be read was served")
	}
}

func TestWindowsPeerSID(t *testing.T) {
	want, err := ownSIDFn()
	if err != nil {
		t.Fatal(err)
	}
	got, err := peerSID(uint32(os.Getpid()))
	if err != nil || !got.Equals(want) {
		t.Fatalf("own pid: %v %v", got, err)
	}
	if _, err := peerSID(0xFFFFFFF0); err == nil {
		t.Error("a pid that does not exist was resolved")
	}
}
