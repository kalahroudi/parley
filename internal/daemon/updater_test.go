// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/release"
	"github.com/kalahroudi/parley/internal/update"
)

func exeName(n string) string {
	if runtime.GOOS == "windows" {
		return n + ".exe"
	}
	return n
}

// signedRelease serves one release of version v as the latest and under its own address, signed by key and valid
// around the real clock.
func signedRelease(t *testing.T, key release.SecretKey, v string, bodies map[string]string) *httptest.Server {
	t.Helper()
	files := map[string][]byte{}
	var sums bytes.Buffer
	for name, body := range bodies {
		asset := fmt.Sprintf("%s_%s_%s_%s", name, v, runtime.GOOS, runtime.GOARCH)
		if runtime.GOOS == "windows" {
			asset += ".exe"
		}
		sum := sha256.Sum256([]byte(body))
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
		files[asset] = []byte(body)
	}
	ver, _ := update.ParseVersion(v)
	sig, err := key.Sign(sums.Bytes(), update.FormatComment(ver, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	files["SHA256SUMS"], files["SHA256SUMS.minisig"] = sums.Bytes(), sig
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := files[r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// installDir makes a private directory holding the two programs, as an install would.
func installDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	os.Chmod(d, 0o700)
	for _, n := range []string{"parleyd", "parley-cli"} {
		os.WriteFile(filepath.Join(d, exeName(n)), []byte("old "+n), 0o755)
	}
	return d
}

func testUpdater(t *testing.T, e *env, pk release.PublicKey, srv *httptest.Server, dir string) *update.Updater {
	t.Helper()
	return &update.Updater{Key: pk, Source: update.HTTPSource{Base: srv.URL}, Current: "v1.0.0", Dir: dir,
		Names: []string{"parleyd", "parley-cli"}, OS: runtime.GOOS, Arch: runtime.GOARCH, LockPath: filepath.Join(e.dirs.State, "update.lock")}
}

func read(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, exeName(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func waitStatus(t *testing.T, e *env, state string) update.Status {
	t.Helper()
	var st update.Status
	waitFor(t, "update status "+state, func() bool {
		s, ok, err := update.ReadStatus(e.dirs.State)
		st = s
		return err == nil && ok && s.State == state
	})
	return st
}

// J: in auto mode a running daemon installs a verified newer release, records it, and says to restart. The log
// carries the component and a version, nothing else.
func TestDaemonInstallsVerifiedUpdateInAutoMode(t *testing.T) {
	sk, pk, _ := release.GenerateKey()
	srv := signedRelease(t, sk, "v1.1.0", map[string]string{"parleyd": "new daemon", "parley-cli": "new cli"})
	dir := installDir(t)
	e := newEnv(t)
	e.start(t, func(d *Deps) { d.UpdateEvery = 5 * time.Millisecond; d.Updater = testUpdater(t, e, pk, srv, dir) })
	st := waitStatus(t, e, update.StateInstalled)
	if st.Available != "v1.1.0" || st.Current != "v1.0.0" {
		t.Fatalf("%+v", st)
	}
	if read(t, dir, "parleyd") != "new daemon" || read(t, dir, "parley-cli") != "new cli" {
		t.Fatal("not installed")
	}
	waitFor(t, "log line", func() bool { return strings.Contains(e.log.String(), "update installed; restart parleyd to run it") })
	if !strings.Contains(e.log.String(), "v1-1-0") || strings.Contains(e.log.String(), srv.URL) {
		t.Fatalf("log: %s", e.log.String())
	}
}

// In check mode the daemon looks and records, and never writes a program.
func TestDaemonOnlyChecksInCheckMode(t *testing.T) {
	sk, pk, _ := release.GenerateKey()
	srv := signedRelease(t, sk, "v1.1.0", map[string]string{"parleyd": "new daemon", "parley-cli": "new cli"})
	dir := installDir(t)
	e := newEnv(t)
	e.cfg.Update = &UpdateConfig{Mode: UpdateCheck, interval: time.Hour}
	e.start(t, func(d *Deps) { d.UpdateEvery = 5 * time.Millisecond; d.Updater = testUpdater(t, e, pk, srv, dir) })
	st := waitStatus(t, e, update.StateAvailable)
	if st.Available != "v1.1.0" {
		t.Fatalf("%+v", st)
	}
	waitFor(t, "log line", func() bool { return strings.Contains(e.log.String(), "update available") })
	time.Sleep(50 * time.Millisecond) // more cycles run; none installs
	if read(t, dir, "parleyd") != "old parleyd" {
		t.Fatal("check mode installed a program")
	}
}

// A release signed by another key is never installed and is reported by reason code only.
func TestDaemonRejectsUpdateSignedByAnotherKey(t *testing.T) {
	other, _, _ := release.GenerateKey()
	_, pk, _ := release.GenerateKey()
	srv := signedRelease(t, other, "v1.1.0", map[string]string{"parleyd": "evil", "parley-cli": "evil"})
	dir := installDir(t)
	e := newEnv(t)
	e.start(t, func(d *Deps) { d.UpdateEvery = 5 * time.Millisecond; d.Updater = testUpdater(t, e, pk, srv, dir) })
	st := waitStatus(t, e, update.StateError)
	if st.Code != "signature" {
		t.Fatalf("%+v", st)
	}
	waitFor(t, "log line", func() bool { return strings.Contains(e.log.String(), "update check failed") })
	if read(t, dir, "parleyd") != "old parleyd" || strings.Contains(e.log.String(), "evil") || !strings.Contains(e.log.String(), "reason=signature") {
		t.Fatalf("log: %s", e.log.String())
	}
}

// The operator's opt-out: off in the file, off in the environment, a bad environment value, and check beating
// auto. In the off cases there is no update component at all, so nothing can contact the release source.
func TestDaemonOptOut(t *testing.T) {
	has := func(r *running) bool {
		for _, c := range r.d.components() {
			if c.Name == "update" {
				return true
			}
		}
		return false
	}
	for name, c := range map[string]struct {
		cfg      *UpdateConfig
		env      string
		want     bool
		wantMode string
		warn     bool
	}{
		"default":                {nil, "", true, UpdateAuto, false},
		"off in the file":        {&UpdateConfig{Mode: UpdateOff, interval: time.Hour}, "", false, UpdateOff, false},
		"off in the environment": {nil, "off", false, UpdateOff, false},
		"bad environment":        {nil, "maybe", false, UpdateOff, true},
		"environment cannot turn on what the file turned off": {&UpdateConfig{Mode: UpdateOff, interval: time.Hour}, "auto", false, UpdateOff, false},
		"environment tightens auto to check":                  {nil, "check", true, UpdateCheck, false},
	} {
		e := newEnv(t)
		e.cfg.Update = c.cfg
		r := e.start(t, func(d *Deps) {
			d.Getenv = func(k string) string {
				if k == UpdateEnv {
					return c.env
				}
				return ""
			}
		})
		if got := has(r); got != c.want || r.d.policy.Mode != c.wantMode {
			t.Errorf("%s: component=%v mode=%q", name, got, r.d.policy.Mode)
		}
		if warned := strings.Contains(e.log.String(), "update policy invalid"); warned != c.warn {
			t.Errorf("%s: warned=%v\n%s", name, warned, e.log.String())
		}
	}
}

// The production path: built from the policy and the running file. A mirror with nothing is a failed check, a
// pin and a mirror reach the updater, and a daemon that is not a release build or is package-managed stays out.
func TestDaemonUpdateProductionPath(t *testing.T) {
	empty := httptest.NewServer(http.NotFoundHandler())
	defer empty.Close()
	d := installDir(t)
	exe := filepath.Join(d, exeName("parleyd"))

	e := newEnv(t)
	e.cfg.Update = &UpdateConfig{Source: empty.URL, interval: time.Hour}
	e.start(t, func(dp *Deps) {
		dp.UpdateEvery = 5 * time.Millisecond
		dp.Version = "v1.0.0"
		dp.Executable = func() (string, error) { return exe, nil }
	})
	if st := waitStatus(t, e, update.StateError); st.Code != "failed" {
		t.Fatalf("%+v", st)
	}

	for name, mod := range map[string]func(*Deps){
		"source build": func(dp *Deps) { dp.Version = "dev" },
		"no executable": func(dp *Deps) {
			dp.Version = "v1.0.0"
			dp.Executable = func() (string, error) { return "", errors.New("none") }
		},
		"not a file": func(dp *Deps) {
			dp.Version = "v1.0.0"
			dp.Executable = func() (string, error) { return filepath.Join(d, "x"), nil }
		},
	} {
		e := newEnv(t)
		e.start(t, func(dp *Deps) {
			dp.Executable = func() (string, error) { return exe, nil }
			mod(dp)
		})
		waitFor(t, name+" to opt out", func() bool { return strings.Contains(e.log.String(), "self-update is off for this installation") })
	}
}

func TestNewUpdater(t *testing.T) {
	d := installDir(t)
	exe := filepath.Join(d, exeName("parleyd"))
	state := t.TempDir()
	if _, err := NewUpdater(UpdatePolicy{}, "dev", exe, state); !errors.Is(err, update.ErrNotRelease) {
		t.Fatalf("dev build: %v", err)
	}
	if _, err := NewUpdater(UpdatePolicy{}, "v1.0.0", filepath.Join(d, "missing"), state); err == nil {
		t.Fatal("missing executable accepted")
	}
	u, err := NewUpdater(UpdatePolicy{}, "v1.0.0", exe, state)
	if err != nil || u.Pin != "" || u.Current != "v1.0.0" || u.OS != runtime.GOOS || u.LockPath != filepath.Join(state, "update.lock") {
		t.Fatalf("%+v %v", u, err)
	}
	if s, _ := u.Source.(update.HTTPSource); s.Base != update.DefaultSource {
		t.Fatalf("default source %q", s.Base)
	}
	if u.Key.ID.String() != "26364667D369282A" {
		t.Fatalf("not the project key: %s", u.Key.ID)
	}
	u, err = NewUpdater(UpdatePolicy{Pin: "v0.9.0", Source: "https://mirror.example/rel"}, "v1.0.0", exe, state)
	if err != nil || u.Pin != "v0.9.0" || u.Source.(update.HTTPSource).Base != "https://mirror.example/rel" {
		t.Fatalf("%+v %v", u, err)
	}
	if _, err := newUpdater([]byte("garbage"), UpdatePolicy{}, "v1.0.0", exe, state); err == nil {
		t.Fatal("bad key accepted")
	}
	if runtime.GOOS != "windows" {
		cellar := filepath.Join(t.TempDir(), "Cellar", "bin")
		os.MkdirAll(cellar, 0o755)
		os.WriteFile(filepath.Join(cellar, "parleyd"), nil, 0o755)
		if _, err := NewUpdater(UpdatePolicy{}, "v1.0.0", filepath.Join(cellar, "parleyd"), state); !errors.Is(err, update.ErrManaged) {
			t.Fatalf("package manager: %v", err)
		}
	}
	if p, err := Executable(); err != nil || p == "" {
		t.Fatalf("Executable: %q %v", p, err)
	}
	if versionID("v1.22.3") != "v1-22-3" {
		t.Fatal("versionID")
	}
}

// A status record that cannot be written is logged and the cycle's own log line still appears.
func TestReportUpdateWhenStatusCannotBeWritten(t *testing.T) {
	var log syncBuf
	d := &Daemon{dirs: Dirs{State: filepath.Join(t.TempDir(), "missing")}, deps: Deps{Log: logx.New(&log)}}
	d.reportUpdate(update.Status{State: update.StateUpToDate, Current: "v1.0.0"})
	d.reportUpdate(update.Status{State: update.StateAvailable, Current: "v1.0.0", Available: "v1.1.0"})
	if strings.Count(log.String(), "update status not recorded") != 2 || !strings.Contains(log.String(), "update available") {
		t.Fatalf("log: %s", log.String())
	}
}
