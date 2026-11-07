// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/fsperm"
	"github.com/kalahroudi/parley/internal/release"
	"github.com/kalahroudi/parley/internal/update"
)

type memSource map[string][]byte

func (m memSource) Fetch(_ context.Context, version, name string, _ int64, w io.Writer) error {
	if version == "" {
		version = "latest"
	}
	b, ok := m[version+"/"+name]
	if !ok {
		return errors.New("not found")
	}
	_, err := w.Write(b)
	return err
}

func exe(n string) string {
	if runtime.GOOS == "windows" {
		return n + ".exe"
	}
	return n
}

// publish signs version v with sk, valid around the real clock, and serves it at its own address and as the latest.
func (m memSource) publish(t *testing.T, sk release.SecretKey, v string, issued, expires time.Time) {
	t.Helper()
	var sums bytes.Buffer
	for _, n := range []string{"parleyd", "parley-cli"} {
		asset := fmt.Sprintf("%s_%s_%s_%s", n, v, runtime.GOOS, runtime.GOARCH)
		if runtime.GOOS == "windows" {
			asset += ".exe"
		}
		body := []byte(n + " " + v)
		sum := sha256.Sum256(body)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
		m[v+"/"+asset], m["latest/"+asset] = body, body
	}
	ver, _ := update.ParseVersion(v)
	sig, err := sk.Sign(sums.Bytes(), update.FormatComment(ver, issued, expires))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{v + "/", "latest/"} {
		m[p+"SHA256SUMS"], m[p+"SHA256SUMS.minisig"] = sums.Bytes(), sig
	}
}

func (m memSource) publishValid(t *testing.T, sk release.SecretKey, v string) {
	t.Helper()
	m.publish(t, sk, v, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
}

type updateEnv struct {
	bin, home string
	src       memSource
	sk        release.SecretKey
	tools     tools
	pols      []daemon.UpdatePolicy
	env       map[string]string
}

func newUpdateEnv(t *testing.T, current string) *updateEnv {
	t.Helper()
	sk, pk, _ := release.GenerateKey()
	e := &updateEnv{bin: t.TempDir(), home: t.TempDir(), src: memSource{}, sk: sk, env: map[string]string{}}
	os.Chmod(e.bin, 0o700)
	for _, n := range []string{"parleyd", "parley-cli"} {
		os.WriteFile(filepath.Join(e.bin, exe(n)), []byte("old "+n), 0o755)
	}
	e.tools = tools{updater: func(pol daemon.UpdatePolicy, state string) (*update.Updater, error) {
		e.pols = append(e.pols, pol)
		return &update.Updater{Key: pk, Source: e.src, Current: current, Pin: pol.Pin, Dir: e.bin, Names: []string{"parleyd", "parley-cli"},
			OS: runtime.GOOS, Arch: runtime.GOARCH, LockPath: filepath.Join(state, "update.lock")}, nil
	}}
	return e
}

func (e *updateEnv) run(args ...string) (int, string, string) {
	var out, errw bytes.Buffer
	getenv := func(k string) string {
		if k == "PARLEY_HOME" {
			return e.home
		}
		return e.env[k]
	}
	code := execute(context.Background(), append([]string{"update"}, args...), strings.NewReader(""), &out, &errw, os.UserConfigDir, getenv, e.tools)
	return code, out.String(), errw.String()
}

func (e *updateEnv) installed(t *testing.T, n string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.bin, exe(n)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (e *updateEnv) writeConfig(t *testing.T, section string) {
	t.Helper()
	pub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := `{"format":1,"tenant":"t1","device_id":"dev-1","gateway_url":"https://gw.example.test","root_public_key":"` + pub + `"` + section + `}`
	if err := os.WriteFile(filepath.Join(e.home, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateCheckThenApply(t *testing.T) {
	e := newUpdateEnv(t, "v1.0.0")
	e.src.publishValid(t, e.sk, "v1.1.0")

	code, out, errw := e.run("check")
	if code != 0 || !strings.Contains(out, "update available: v1.1.0") || errw != "" {
		t.Fatalf("check: %d %q %q", code, out, errw)
	}
	if e.installed(t, "parleyd") != "old parleyd" {
		t.Fatal("check installed something")
	}
	code, out, errw = e.run("apply")
	if code != 0 || !strings.Contains(out, "updated to v1.1.0") || !strings.Contains(out, "restart parleyd") || errw != "" {
		t.Fatalf("apply: %d %q %q", code, out, errw)
	}
	if e.installed(t, "parleyd") != "parleyd v1.1.0" || e.installed(t, "parley-cli") != "parley-cli v1.1.0" {
		t.Fatal("not installed")
	}
	// status shows the record the apply left.
	code, out, _ = e.run("status")
	if code != 0 || !strings.Contains(out, "mode: auto") || !strings.Contains(out, "installed") || !strings.Contains(out, "release: v1.1.0") {
		t.Fatalf("status: %d %q", code, out)
	}
}

func TestUpdateUpToDateAndStatusWithoutRecord(t *testing.T) {
	e := newUpdateEnv(t, "v1.1.0")
	e.src.publishValid(t, e.sk, "v1.1.0")
	if code, out, _ := e.run("status"); code != 0 || !strings.Contains(out, "last check: none recorded") || !strings.Contains(out, "version: dev") {
		t.Fatalf("%d %q", code, out)
	}
	for _, sub := range []string{"check", "apply"} {
		if code, out, _ := e.run(sub); code != 0 || !strings.Contains(out, "up to date: v1.1.0") {
			t.Fatalf("%s: %d %q", sub, code, out)
		}
	}
}

// A feed that does not verify is reported by a fixed reason, exits 1 and changes nothing, in check and apply alike.
func TestUpdateFailuresPrintReasonsOnly(t *testing.T) {
	e := newUpdateEnv(t, "v1.0.0")
	other, _, _ := release.GenerateKey()
	cases := map[string]func(){
		"signature": func() { e.src.publishValid(t, other, "v1.1.0") },
		"expired": func() {
			e.src.publish(t, e.sk, "v1.1.0", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
		},
		"not_yet": func() {
			e.src.publish(t, e.sk, "v1.1.0", time.Now().Add(time.Hour), time.Now().Add(48*time.Hour))
		},
	}
	for code, publish := range cases {
		publish()
		for _, sub := range []string{"check", "apply"} {
			c, out, errw := e.run(sub)
			if c != 1 || out != "" || !strings.Contains(errw, "update failed: "+code+" ("+codeHelp[code]+")") {
				t.Errorf("%s %s: %d %q %q", code, sub, c, out, errw)
			}
		}
		if e.installed(t, "parleyd") != "old parleyd" {
			t.Errorf("%s: installed", code)
		}
		if _, out, _ := e.run("status"); !strings.Contains(out, "reason: "+code) {
			t.Errorf("%s: status %q", code, out)
		}
	}
	// A source that is down.
	e.src = memSource{}
	e.tools.updater = func(pol daemon.UpdatePolicy, state string) (*update.Updater, error) {
		return &update.Updater{Source: e.src, Current: "v1.0.0", Dir: e.bin, Names: []string{"parleyd"}, OS: runtime.GOOS, Arch: runtime.GOARCH}, nil
	}
	if c, _, errw := e.run("check"); c != 1 || !strings.Contains(errw, "failed ("+codeHelp["failed"]+")") {
		t.Fatalf("%d %q", c, errw)
	}
}

// JJ-01 from the command line: -version installs exactly that version (older included) and the pin in config.json
// holds without the flag.
func TestUpdatePinFromFlagAndConfig(t *testing.T) {
	e := newUpdateEnv(t, "v2.0.0")
	e.src.publishValid(t, e.sk, "v1.5.0")
	e.src.publishValid(t, e.sk, "v3.0.0") // the latest
	if code, out, errw := e.run("apply", "-version", "v1.5.0"); code != 0 || !strings.Contains(out, "updated to v1.5.0") {
		t.Fatalf("%d %q %q", code, out, errw)
	}
	if e.installed(t, "parleyd") != "parleyd v1.5.0" {
		t.Fatal("pinned version not installed")
	}
	if code, _, errw := e.run("check", "-version", "latest"); code != 1 || !strings.Contains(errw, "pin") {
		t.Fatalf("%d %q", code, errw)
	}

	e2 := newUpdateEnv(t, "v1.5.0")
	e2.src.publishValid(t, e2.sk, "v1.5.0")
	e2.src.publishValid(t, e2.sk, "v3.0.0")
	e2.writeConfig(t, `,"update":{"pin":"v1.5.0","source":"https://mirror.example/rel"}`)
	code, out, errw := e2.run("apply")
	if code != 0 || !strings.Contains(out, "up to date: v1.5.0") || e2.pols[0].Pin != "v1.5.0" || e2.pols[0].Source != "https://mirror.example/rel" {
		t.Fatalf("%d %q %q %+v", code, out, errw, e2.pols)
	}
	if e2.installed(t, "parleyd") != "old parleyd" {
		t.Fatal("the pin did not hold")
	}
	if _, out, _ := e2.run("status"); !strings.Contains(out, "pinned to: v1.5.0") || !strings.Contains(out, "source: https://mirror.example/rel") {
		t.Fatalf("status: %q", out)
	}
}

// The operator's opt-out: off in config.json or PARLEY_UPDATE refuses check and apply before anything is built or
// contacted; status still works and says why. A bad PARLEY_UPDATE value means off too.
func TestUpdateOptOut(t *testing.T) {
	for name, set := range map[string]func(e *updateEnv, t *testing.T){
		"config off":          func(e *updateEnv, t *testing.T) { e.writeConfig(t, `,"update":{"mode":"off"}`) },
		"environment off":     func(e *updateEnv, t *testing.T) { e.env["PARLEY_UPDATE"] = "off" },
		"environment garbage": func(e *updateEnv, t *testing.T) { e.env["PARLEY_UPDATE"] = "yes please" },
	} {
		e := newUpdateEnv(t, "v1.0.0")
		e.src.publishValid(t, e.sk, "v1.1.0")
		set(e, t)
		for _, sub := range []string{"check", "apply"} {
			code, out, errw := e.run(sub)
			if code != 1 || out != "" || !strings.Contains(errw, "updates are turned off") || len(e.pols) != 0 {
				t.Errorf("%s %s: %d %q %q (updaters built: %d)", name, sub, code, out, errw, len(e.pols))
			}
		}
		if e.installed(t, "parleyd") != "old parleyd" {
			t.Errorf("%s: installed", name)
		}
		if code, out, _ := e.run("status"); code != 0 || !strings.Contains(out, "mode: off") {
			t.Errorf("%s: status %d %q", name, code, out)
		}
	}
	e := newUpdateEnv(t, "v1.0.0")
	e.env["PARLEY_UPDATE"] = "bad"
	if _, out, _ := e.run("status"); !strings.Contains(out, "PARLEY_UPDATE has a value") {
		t.Fatalf("status did not explain: %q", out)
	}
	if _, _, errw := e.run("apply"); !strings.Contains(errw, "PARLEY_UPDATE has a value") {
		t.Fatalf("apply did not explain: %q", errw)
	}
}

// check mode lets an explicit apply through (the operator asked), but PARLEY_UPDATE=check does too: only off blocks.
func TestUpdateApplyIsAllowedInCheckMode(t *testing.T) {
	e := newUpdateEnv(t, "v1.0.0")
	e.src.publishValid(t, e.sk, "v1.1.0")
	e.env["PARLEY_UPDATE"] = "check"
	if code, out, _ := e.run("apply"); code != 0 || !strings.Contains(out, "updated to v1.1.0") {
		t.Fatalf("%d %q", code, out)
	}
}

// A config.json that exists but is broken must not silently drop an opt-out or a pin.
func TestUpdateRefusesWithBrokenConfig(t *testing.T) {
	e := newUpdateEnv(t, "v1.0.0")
	e.writeConfig(t, `,"update":{"mode":"sometimes"}`)
	for _, sub := range []string{"status", "check", "apply"} {
		if code, _, errw := e.run(sub); code != 1 || !strings.Contains(errw, "config.json is invalid") || len(e.pols) != 0 {
			t.Errorf("%s: %d %q", sub, code, errw)
		}
	}
}

func TestUpdateBusyLeavesTheRecordAlone(t *testing.T) {
	e := newUpdateEnv(t, "v1.0.0")
	e.src.publishValid(t, e.sk, "v1.1.0")
	state, _ := daemon.DefaultDirs(func(string) string { return e.home }, os.UserConfigDir)
	prev := update.Status{State: update.StateUpToDate, CheckedAt: 5, Current: "v1.0.0"}
	update.WriteStatus(state.State, prev)
	release, err := fsperm.Lock(filepath.Join(state.State, "update.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if code, _, errw := e.run("apply"); code != 1 || !strings.Contains(errw, "busy") {
		t.Fatalf("%d %q", code, errw)
	}
	if got, _, _ := update.ReadStatus(state.State); got != prev {
		t.Fatalf("record overwritten: %+v", got)
	}
	if e.installed(t, "parleyd") != "old parleyd" {
		t.Fatal("installed while another update ran")
	}
}

func TestUpdateUsageAndUnreadableRecord(t *testing.T) {
	e := newUpdateEnv(t, "v1.0.0")
	for _, args := range [][]string{{}, {"bogus"}, {"apply", "extra"}, {"apply", "-bogus"}, {"status", "-version", "v1.0.0"}, {"check", "-version"}} {
		if code, _, errw := e.run(args...); code != 2 || !strings.Contains(errw, "usage: parley-cli update") {
			t.Errorf("%v: %d %q", args, code, errw)
		}
	}
	os.WriteFile(filepath.Join(e.home, update.StatusFile), []byte("junk"), 0o600)
	if code, _, errw := e.run("status"); code != 1 || !strings.Contains(errw, "unreadable") {
		t.Fatalf("%d %q", code, errw)
	}
	var out, errb bytes.Buffer
	if code := execute(context.Background(), []string{"update", "status"}, strings.NewReader(""), &out, &errb, func() (string, error) { return "", errors.New("no home") }, func(string) string { return "" }, e.tools); code != 1 || !strings.Contains(errb.String(), "no home") {
		t.Fatalf("%d %q", code, errb.String())
	}
	// An installation that cannot build an updater says why.
	e.tools.updater = func(daemon.UpdatePolicy, string) (*update.Updater, error) { return nil, update.ErrManaged }
	if code, _, errw := e.run("apply"); code != 1 || !strings.Contains(errw, "package manager") {
		t.Fatalf("%d %q", code, errw)
	}
}

// A build from source or `go install` has no release version and is never replaced, whatever the source says.
func TestUpdateRefusesSourceBuilds(t *testing.T) {
	var out, errw bytes.Buffer
	home := t.TempDir()
	code := execute(context.Background(), []string{"update", "apply"}, strings.NewReader(""), &out, &errw, os.UserConfigDir, func(k string) string {
		if k == "PARLEY_HOME" {
			return home
		}
		return ""
	}, defaultTools())
	if code != 1 || !strings.Contains(errw.String(), "not a release build") || out.Len() != 0 {
		t.Fatalf("%d %q %q", code, out.String(), errw.String())
	}
}
