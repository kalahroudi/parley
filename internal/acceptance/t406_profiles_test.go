// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// The OS sandbox profiles shipped in docs/sandbox, which cover what Parley alone cannot (a process of the same user
// that Parley did not start): they must parse and, where the OS allows it on a CI runner, they must keep a process
// from connecting to a live daemon's socket.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sandboxFile(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "docs", "sandbox", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	return p
}

// dialFrom runs this test binary as a "dial" bot behind the given command prefix and returns what it reported.
func dialFrom(t *testing.T, sock string, prefix ...string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := append(prefix[1:], exe)
	cmd := exec.CommandContext(ctx, prefix[0], args...)
	cmd.Env = append(os.Environ(), t406Env+"=dial", "PARLEY_T406_SOCK="+sock)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v: %v: %s", prefix, err, stderr.String())
	}
	var line struct{ Content []byte }
	if err := json.Unmarshal(out, &line); err != nil {
		t.Fatalf("%q: %v", out, err)
	}
	return string(line.Content)
}

func TestSandboxProfilesAreShippedAndStateWhatTheyDo(t *testing.T) {
	mac, err := os.ReadFile(sandboxFile(t, "macos.sb"))
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"(version 1)", "(deny network-outbound (remote unix-socket))", "(deny network-bind (local unix-socket))"} {
		if !strings.Contains(string(mac), rule) {
			t.Errorf("macos.sb lacks %s", rule)
		}
	}
	sh, err := os.ReadFile(sandboxFile(t, "linux-bwrap.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--tmpfs \"$state\"", "--unshare-pid", "--new-session", "--die-with-parent"} {
		if !strings.Contains(string(sh), flag) {
			t.Errorf("linux-bwrap.sh lacks %s", flag)
		}
	}
	if win, err := os.ReadFile(sandboxFile(t, "windows.md")); err != nil || !strings.Contains(string(win), "runas /user:") {
		t.Errorf("windows.md: %v", err)
	}
}

func TestLinuxSandboxScriptParses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the script is for Linux; Windows runners have no POSIX shell to parse it with")
	}
	if out, err := exec.Command("sh", "-n", sandboxFile(t, "linux-bwrap.sh")).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}

// Under the macOS profile a process told the daemon's socket path cannot connect; without it the same process can.
func TestMacOSProfileKeepsAProcessAwayFromTheSocket(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("sandbox-exec exists on macOS only")
	}
	g := newPipeGW(t)
	n := g.startOK("sbx7", nodeOpts{})
	sock := n.dirs.SocketPath()
	if got := dialFrom(t, sock, "/usr/bin/env"); got != "connected" {
		t.Fatalf("the control failed: an unsandboxed same-user process %q", got)
	}
	if got := dialFrom(t, sock, "/usr/bin/sandbox-exec", "-f", sandboxFile(t, "macos.sb")); got != "refused" {
		t.Errorf("under the macOS profile the process %q", got)
	}
}

// Under the Linux script a process told the daemon's socket path cannot connect. The runner must allow unprivileged user
// namespaces (some do not); where bubblewrap cannot start at all the test says so instead of passing.
func TestLinuxSandboxScriptKeepsAProcessAwayFromTheSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("bubblewrap exists on Linux only")
	}
	if out, err := exec.Command("bwrap", "--ro-bind", "/", "/", "--unshare-user", "true").CombinedOutput(); err != nil {
		t.Skipf("bubblewrap cannot start here (%v: %s), so the profile was not run on this machine", err, strings.TrimSpace(string(out)))
	}
	g := newPipeGW(t)
	n := g.startOK("sbx8", nodeOpts{})
	sock := n.dirs.SocketPath()
	if got := dialFrom(t, sock, "/usr/bin/env"); got != "connected" {
		t.Fatalf("the control failed: an unsandboxed same-user process %q", got)
	}
	if got := dialFrom(t, sock, sandboxFile(t, "linux-bwrap.sh"), filepath.Dir(sock)); got != "refused" {
		t.Errorf("under the Linux script the process %q", got)
	}
}
