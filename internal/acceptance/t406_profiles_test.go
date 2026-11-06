// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// The OS sandbox profiles shipped in docs/sandbox, which cover what Parley alone cannot (a process of the same user
// that Parley did not start): they must parse and, where the OS allows it on a CI runner, they must keep a process
// from connecting to a live daemon's socket.

import (
	"context"
	"encoding/json"
	"fmt"
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
	win, err := os.ReadFile(sandboxFile(t, "windows.md"))
	if err != nil || !strings.Contains(string(win), "Not verified on a second user account") {
		t.Errorf("windows.md must say the profile is not verified: %v", err)
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
	fmt.Println("SANDBOX-PROFILE macos: RAN, the process was refused")
}

// Under the Linux script a process told the daemon's socket path cannot connect. The runner must allow unprivileged user
// namespaces (some do not); where bubblewrap cannot start at all the test says so instead of passing.
func TestLinuxSandboxScriptKeepsAProcessAwayFromTheSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("bubblewrap exists on Linux only")
	}
	if out, err := exec.Command("bwrap", "--ro-bind", "/", "/", "--unshare-user", "true").CombinedOutput(); err != nil {
		msg := fmt.Sprintf("bubblewrap cannot start here (%v: %s)", err, strings.TrimSpace(string(out)))
		if os.Getenv("CI") != "" {
			t.Fatalf("%s; CI must run the Linux sandbox profile (install bubblewrap and allow user namespaces)", msg)
		}
		fmt.Println("SANDBOX-PROFILE linux: SKIPPED outside CI:", msg)
		t.Skip(msg)
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
	fmt.Println("SANDBOX-PROFILE linux: RAN, the process was refused")
}

// The Windows script is not verified on a second user account (docs/sandbox/windows.md says so); what is tested is that it
// parses, that its dry run prints the commands and runs nothing, and that it refuses a hostile user name or bot path.
func TestWindowsSandboxScriptParsesAndDryRuns(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell's parser is checked on the Windows runners")
	}
	script := sandboxFile(t, "windows.ps1")
	parse := `$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile($env:PARLEY_PS1,[ref]$t,[ref]$e);if($e.Count){$e|%{$_.Message};exit 1}`
	check := exec.Command("powershell", "-NoProfile", "-Command", parse)
	check.Env = append(os.Environ(), "PARLEY_PS1="+script)
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("does not parse: %v: %s", err, out)
	}
	run := func(args ...string) (string, error) {
		out, err := exec.Command("powershell", append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script}, args...)...).CombinedOutput()
		return string(out), err
	}
	out, err := run("-Bot", `C:otsot.exe`, "-DryRun")
	want := "would run: net user parley-bot * /add"
	if err != nil || !strings.Contains(out, want) || !strings.Contains(out, `would run: runas /user:parley-bot "C:otsot.exe"`) {
		t.Errorf("dry run: %v %q", err, out)
	}
	if _, err := run("-Bot", `C:otsot.exe`, "-User", "x & calc", "-DryRun"); err == nil {
		t.Error("a hostile user name was accepted")
	}
	if _, err := run("-Bot", `C:ots"bot.exe`, "-DryRun"); err == nil {
		t.Error("a bot path with a quote was accepted")
	}
	fmt.Println("SANDBOX-PROFILE windows: script parsed and dry-run checked; enforcement NOT verified on a second user")
}
