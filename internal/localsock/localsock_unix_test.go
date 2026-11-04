// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

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

	"github.com/kalahroudi/parley/internal/logx"
)

func TestSocketIsPrivate(t *testing.T) {
	ts := startServer(t, nil)
	fi, err := os.Stat(ts.path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode: %v %v", fi.Mode(), err)
	}
	di, _ := os.Stat(filepath.Dir(ts.path))
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode: %v", di.Mode())
	}
}

func TestSocketRefusesOtherUsers(t *testing.T) {
	m := map[string]Method{"x": func(context.Context, json.RawMessage) (any, error) { return 1, nil }}
	// A server that only admits another uid sees this process as a stranger.
	ts := startServerAs(t, os.Geteuid()+1, m)
	r, err := Call(context.Background(), ts.path, "x", nil)
	if err == nil && r.OK {
		t.Fatal("a connection from a different uid was served")
	}
	waitFor(t, "refusal logged", func() bool { return strings.Contains(ts.log.String(), "not this user") })
	if own := startServer(t, m); true {
		if r, err := Call(context.Background(), own.path, "x", nil); err != nil || !r.OK {
			t.Errorf("own uid must be served: %+v %v", r, err)
		}
	}
}

func TestListenRestrictFailure(t *testing.T) {
	old := chmod
	chmod = func(string, os.FileMode) error { return errors.New("boom") }
	defer func() { chmod = old }()
	p := filepath.Join(tempDir(t), "s", "d.sock")
	if _, err := Listen(p); err == nil {
		t.Fatal("a socket that could not be restricted must not be served")
	}
	if _, err := net.Dial("unix", p); err == nil {
		t.Error("the unrestricted listener was left open")
	}
}

func TestRefusedPeerDoesNotStopTheServer(t *testing.T) {
	path := filepath.Join(tempDir(t), "s", "d.sock")
	real, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe() // carries no peer credentials: refused
	defer b.Close()
	ln := &chainListener{first: a, Listener: real}
	s := &Server{Log: logx.New(&syncBuf{}), UID: os.Geteuid(), Methods: map[string]Method{"x": func(context.Context, json.RawMessage) (any, error) { return 1, nil }}}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() { s.Serve(ctx, ln); close(finished) }()
	defer func() { cancel(); <-finished }()
	if r, err := Call(context.Background(), path, "x", nil); err != nil || !r.OK {
		t.Errorf("a refused connection must not stop later ones being served: %+v %v", r, err)
	}
}

// chainListener's first Accept returns a fixed connection.
type chainListener struct {
	net.Listener
	first net.Conn
}

func (c *chainListener) Accept() (net.Conn, error) {
	if f := c.first; f != nil {
		c.first = nil
		return f, nil
	}
	return c.Listener.Accept()
}
