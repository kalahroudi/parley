// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package acceptance

// T505: docs/windows/install.ps1 performed for real on the Windows runner: install (copies, launcher, HKCU Run
// value), the Run command executed the way Windows runs it at logon, the daemon answering on its socket, a
// termination followed by another start from the Run command (a stale socket and lock must not stop it), and the
// uninstall that stops the daemon and removes the Run value and every file it installed.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

func installScript(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "docs", "windows", "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ps(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("powershell.exe", append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"}, args...)...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("powershell %v: %v\n%s", args, err, out.String())
	}
	return out.String()
}

// The script touches only the user's hive and profile: no machine-wide registry, Program Files, service or task.
func TestWindowsInstallScriptIsPerUser(t *testing.T) {
	b, err := os.ReadFile(installScript(t))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") { // the header comment names what the script does not do
			lines = append(lines, l)
		}
	}
	code := strings.ToLower(strings.Join(lines, "\n"))
	for _, bad := range []string{"hklm", "program files", "programdata", "sc.exe", "new-service", "schtasks", "register-scheduledtask", "runas", "start-process -verb"} {
		if strings.Contains(code, bad) {
			t.Errorf("install.ps1 mentions %q: it must stay per-user and need no administrator", bad)
		}
	}
	if !strings.Contains(code, `hkcu:\software\microsoft\windows\currentversion\run`) || !strings.Contains(code, "localappdata") {
		t.Error("install.ps1 no longer uses the HKCU Run key and the profile")
	}
}

func TestWindowsInstallAutostartUninstall(t *testing.T) {
	exe := parleydExe(t)
	bin := filepath.Dir(exe)
	// parley-cli is installed beside the daemon: build it too.
	cli := filepath.Join(bin, "parley-cli.exe")
	if out, err := exec.Command("go", "build", "-o", cli, "github.com/kalahroudi/parley/cmd/parley-cli").CombinedOutput(); err != nil {
		t.Fatalf("building parley-cli: %v\n%s", err, out)
	}
	home := shortHome(t)
	inst, err := os.MkdirTemp("", "pi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(inst) })
	inst = filepath.Join(inst, "bin")
	const runName = "ParleyT505Test"
	t.Cleanup(func() { // never leave the test's Run value behind, whatever failed
		if k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE); err == nil {
			k.DeleteValue(runName)
			k.Close()
		}
		exec.Command("taskkill", "/F", "/IM", "parleyd.exe", "/FI", "IMAGENAME eq parleyd.exe").Run()
	})
	script := installScript(t)

	out := ps(t, script, "-Action", "Install", "-BinDir", bin, "-InstallDir", inst, "-DaemonHome", home, "-RunName", runName, "-NoStart")
	t.Log(out)
	for _, f := range []string{"parleyd.exe", "parley-cli.exe", "start-parleyd.ps1"} {
		if _, err := os.Stat(filepath.Join(inst, f)); err != nil {
			t.Fatalf("install did not create %s: %v", f, err)
		}
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	runCmd, _, err := k.GetStringValue(runName)
	k.Close()
	if err != nil || !strings.Contains(runCmd, "start-parleyd.ps1") {
		t.Fatalf("the Run value is %q (%v)", runCmd, err)
	}

	// What Windows does at logon: run the value's command line.
	logon := func() {
		t.Helper()
		c := exec.Command("powershell.exe")
		c.SysProcAttr = &syscall.SysProcAttr{CmdLine: runCmd} // the value verbatim, as the Run key's launcher passes it
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("the Run command failed: %v\n%s", err, out)
		}
	}
	up := &runningDaemon{home: home}
	waitAnswers := func(what string) {
		t.Helper()
		for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
			if up.answers() {
				return
			}
		}
		t.Fatalf("%s: the daemon did not answer on its socket in 60 s", what)
	}
	daemonRunning := func() bool {
		out, _ := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			`@(Get-Process -Name parleyd -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq '`+filepath.Join(inst, "parleyd.exe")+`' }).Count`).Output()
		return strings.TrimSpace(string(out)) != "0"
	}

	logon()
	waitAnswers("first logon")
	if !daemonRunning() {
		t.Fatal("the daemon that answers is not the installed one")
	}

	// A terminated daemon leaves its lock file and socket; the next logon must start cleanly on them.
	if out, err := exec.Command("taskkill", "/F", "/IM", "parleyd.exe").CombinedOutput(); err != nil {
		t.Fatalf("taskkill: %v\n%s", err, out)
	}
	for deadline := time.Now().Add(30 * time.Second); up.answers() && time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
	}
	logon()
	waitAnswers("restart after termination")

	out = ps(t, script, "-Action", "Uninstall", "-InstallDir", inst, "-RunName", runName)
	t.Log(out)
	if daemonRunning() || up.answers() {
		t.Error("the daemon still runs after uninstall")
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE); err == nil {
		if _, _, err := k.GetStringValue(runName); err == nil {
			t.Error("the Run value is still there after uninstall")
		}
		k.Close()
	}
	if _, err := os.Stat(inst); !os.IsNotExist(err) {
		t.Errorf("the install folder is still there after uninstall: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "config.json")); err != nil {
		t.Errorf("uninstall must leave the user's configuration alone: %v", err)
	}
}
