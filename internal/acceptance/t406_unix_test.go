// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package acceptance

import (
	"context"
	"encoding/json"
	"syscall"
	"testing"
	"time"
)

// openSockets lists the file descriptors above stderr that are sockets: what a
// bot would hold if the daemon had leaked a connection or its listener to it.
func openSockets() []int {
	var out []int
	for fd := 3; fd < 256; fd++ {
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) == nil && uint32(st.Mode)&syscall.S_IFMT == syscall.S_IFSOCK {
			out = append(out, fd)
		}
	}
	return out
}

// A descriptor the daemon inherited from whatever started it (not close-on-exec) must not reach a bot.
func TestBotDoesNotInheritALeakedSocket(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0) // the syscall package opens it without close-on-exec
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := t406CLI(t, "probe", t.TempDir()).Handle(ctx, t406Task, &countSession{})
	if err != nil {
		t.Fatal(err)
	}
	var rep probeReport
	if err := json.Unmarshal(res, &rep); err != nil {
		t.Fatalf("%q: %v", res, err)
	}
	if len(rep.Sockets) != 0 {
		t.Errorf("the bot inherited the leaked socket %d: %v", fd, rep.Sockets)
	}
}
