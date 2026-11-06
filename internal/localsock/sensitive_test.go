// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package localsock

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kalahroudi/parley/internal/logx"
)

// serveSensitive serves a "change" method that counts its calls (sensitive) and a "look" method (not), with the given guard.
func serveSensitive(t *testing.T, guard func(pid int) error, sensitive map[string]bool) (path string, changed *atomic.Int32, log *syncBuf) {
	t.Helper()
	path = filepath.Join(tempDir(t), "s", "d.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	changed = &atomic.Int32{}
	log = &syncBuf{}
	s := &Server{Log: logx.New(log), UID: os.Geteuid(), Sensitive: sensitive, Guard: guard, Methods: map[string]Method{
		"change": func(context.Context, json.RawMessage) (any, error) { changed.Add(1); return "done", nil },
		"look":   func(context.Context, json.RawMessage) (any, error) { return "seen", nil },
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return path, changed, log
}

func swapPeerPID(t *testing.T, f func(net.Conn) (int, error)) {
	t.Helper()
	old := peerPIDFn
	peerPIDFn = f
	t.Cleanup(func() { peerPIDFn = old })
}

// A sensitive method is served only when the caller's pid is known and the Guard accepts it; every other case is
// refused with the same fixed code and the method never runs.
func TestSensitiveMethodsFailClosed(t *testing.T) {
	sens := map[string]bool{"change": true}
	seen := -1
	allow := func(pid int) error { seen = pid; return nil }
	refuse := func(int) error { return errors.New("a bot") }
	for name, tc := range map[string]struct {
		guard func(int) error
		pid   func(net.Conn) (int, error)
		want  bool // served
	}{
		"allowed caller":                {allow, func(net.Conn) (int, error) { return 4242, nil }, true},
		"guard refuses":                 {refuse, func(net.Conn) (int, error) { return 4242, nil }, false},
		"pid cannot be read":            {allow, func(net.Conn) (int, error) { return 0, errors.New("no pid") }, false},
		"pid is zero":                   {allow, func(net.Conn) (int, error) { return 0, nil }, false},
		"pid is negative":               {allow, func(net.Conn) (int, error) { return -1, nil }, false},
		"no guard configured":           {nil, func(net.Conn) (int, error) { return 4242, nil }, false},
		"no guard and pid unreadable":   {nil, func(net.Conn) (int, error) { return 0, errors.New("x") }, false},
		"pid unreadable, guard refuses": {refuse, func(net.Conn) (int, error) { return 0, errors.New("x") }, false},
	} {
		t.Run(name, func(t *testing.T) {
			swapPeerPID(t, tc.pid)
			seen = -1
			path, changed, log := serveSensitive(t, tc.guard, sens)
			r, err := Call(context.Background(), path, "change", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want {
				if !r.OK || changed.Load() != 1 || seen != 4242 {
					t.Errorf("not served: %+v changed %d pid %d", r, changed.Load(), seen)
				}
				return
			}
			if r.OK || r.Error != CodeNotPermitted || changed.Load() != 0 || len(r.Result) != 0 {
				t.Errorf("served or wrong refusal: %+v changed %d", r, changed.Load())
			}
			if !strings.Contains(log.String(), "refused") {
				t.Errorf("the refusal was not logged: %q", log.String())
			}
		})
	}
}

// Methods that are not sensitive never read the pid or call the Guard, and an unknown method is reported as unknown.
func TestNonSensitiveMethodsIgnoreTheGuard(t *testing.T) {
	var asked atomic.Int32
	swapPeerPID(t, func(net.Conn) (int, error) { asked.Add(1); return 0, errors.New("no pid") })
	path, _, _ := serveSensitive(t, func(int) error { asked.Add(1); return errors.New("no") }, map[string]bool{"change": true})
	if r, err := Call(context.Background(), path, "look", nil); err != nil || !r.OK {
		t.Fatalf("look: %+v %v", r, err)
	}
	if r, err := Call(context.Background(), path, "nothing", nil); err != nil || r.Error != "unknown_method" {
		t.Fatalf("unknown: %+v %v", r, err)
	}
	if asked.Load() != 0 {
		t.Errorf("the guard or the pid lookup ran for a method that is not sensitive")
	}
}

// With the real kernel lookup, a sensitive request from this very process reaches the Guard with this process's pid.
func TestSensitiveMethodSeesTheRealCallerPID(t *testing.T) {
	var got atomic.Int64
	path, changed, _ := serveSensitive(t, func(pid int) error { got.Store(int64(pid)); return nil }, map[string]bool{"change": true})
	if r, err := Call(context.Background(), path, "change", nil); err != nil || !r.OK || changed.Load() != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if int(got.Load()) != os.Getpid() {
		t.Errorf("the guard saw pid %d, this process is %d", got.Load(), os.Getpid())
	}
}

func TestPeerPIDOfAnInvalidConnection(t *testing.T) {
	if _, err := peerPID(&net.UnixConn{}); err == nil {
		t.Error("an invalid connection has no peer pid")
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	if _, err := peerPID(c1); err == nil {
		t.Error("a connection that is not a unix socket has no peer pid")
	}
}
