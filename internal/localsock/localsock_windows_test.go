// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package localsock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

// A process whose token cannot be opened, and a token whose user cannot be read, are errors, never a match.
func TestWindowsPeerSIDTokenErrors(t *testing.T) {
	old := openProcessToken
	t.Cleanup(func() { openProcessToken = old })
	openProcessToken = func(windows.Handle, uint32, *windows.Token) error { return errors.New("denied") }
	if _, err := peerSID(uint32(os.Getpid())); err == nil {
		t.Error("a token that cannot be opened was accepted")
	}
	if _, err := tokenSID(windows.Token(0)); err == nil {
		t.Error("an invalid token yielded a user")
	}
}

// The pid from the kernel must be both readable and positive; a failed read that still left a pid, and a pid of 0 with no error, are refused
// even when the token lookup of that pid would name the daemon's own user.
func TestWindowsPeerPIDMustBeReadableAndPositive(t *testing.T) {
	own, err := ownSIDFn()
	if err != nil {
		t.Fatal(err)
	}
	oldPID, oldSID := checkPIDFn, peerSIDFn
	t.Cleanup(func() { checkPIDFn, peerSIDFn = oldPID, oldSID })
	peerSIDFn = func(uint32) (*windows.SID, error) { return own, nil }
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	for name, f := range map[string]func(net.Conn) (int, error){
		"error with a pid": func(net.Conn) (int, error) { return os.Getpid(), errors.New("boom") },
		"pid zero":         func(net.Conn) (int, error) { return 0, nil },
	} {
		checkPIDFn = f
		if err := checkPeer(srv, 0); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	checkPIDFn = func(net.Conn) (int, error) { return os.Getpid(), nil }
	if err := checkPeer(srv, 0); err != nil {
		t.Errorf("a readable positive pid of the own user was refused: %v", err)
	}
}

// The peer check must not refuse a real peer under load: many calls at once from this process, and from many
// short-lived child processes (what parley-cli is), each with a pid the daemon has never seen. A refusal here is a
// flake in the check, which an operator would see as "daemon not reachable".
func TestWindowsPeerCheckUnderLoad(t *testing.T) {
	ts := startServer(t, okMethod)
	var wg sync.WaitGroup
	var bad atomic.Int32
	var first atomic.Value
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 150; i++ {
				if r, err := Call(context.Background(), ts.path, "x", nil); err != nil || !r.OK {
					bad.Add(1)
					first.CompareAndSwap(nil, fmt.Sprintf("%+v %v", r, err))
				}
			}
		}()
	}
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Fatalf("%d of 1200 in-process calls were refused or failed; first: %v\nserver log:\n%s", n, first.Load(), ts.log.String())
	}

	sem := make(chan struct{}, 6)
	for i := 0; i < 60; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsPeerLoadChild$")
			cmd.Env = append(os.Environ(), "PARLEY_LOAD_CHILD="+ts.path)
			if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "LOAD-OK") {
				bad.Add(1)
				first.CompareAndSwap(nil, fmt.Sprintf("child: %v %s", err, out))
			}
		}()
	}
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Fatalf("%d of 60 child-process calls were refused or failed; first: %v\nserver log:\n%s", n, first.Load(), ts.log.String())
	}
}

// TestWindowsPeerLoadChild is the child of TestWindowsPeerCheckUnderLoad; it does nothing in a normal run.
func TestWindowsPeerLoadChild(t *testing.T) {
	path := os.Getenv("PARLEY_LOAD_CHILD")
	if path == "" {
		t.Skip("helper process")
	}
	for i := 0; i < 3; i++ {
		if r, err := Call(context.Background(), path, "x", nil); err != nil || !r.OK {
			t.Fatalf("call %d: %+v %v", i, r, err)
		}
	}
	os.Stdout.WriteString("LOAD-OK\n")
}
