// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/keystore"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/root"
)

var bg = context.Background()

func TestEnrollWithASessionEndToEnd(t *testing.T) {
	e := newEnv(t)
	e.gw.set(func(g *fakeGateway) { g.pending = 2 })
	var logs bytes.Buffer
	e.opts.Log = logx.New(&logs)
	res, err := Enroll(bg, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	cfg := res.Config
	if e.gw.pollCount() != 3 || cfg.Tenant != "acme" || cfg.GatewayURL != e.gw.srv.URL || !bytes.Equal(cfg.RootPublicKey, e.gw.rootPub) || len(res.Replaced) != 0 {
		t.Fatalf("polls=%d cfg=%+v res=%+v", e.gw.pollCount(), cfg, res)
	}
	var rq *fakeReq
	for id, r := range e.gw.snapshot() {
		rq = r
		if id != cfg.DeviceID {
			t.Errorf("config names device %s, the request was %s", cfg.DeviceID, id)
		}
	}
	// What was sent: the session as a bearer, the name, and the public half of the one stored key.
	if rq.auth != "Bearer ps_acme."+strings.Repeat("a", 64) || rq.name != "laptop" || !bytes.Equal(rq.key, e.keys.key.Public().(ed25519.PublicKey)) || e.keys.saves != 1 {
		t.Errorf("request %+v saves=%d", rq, e.keys.saves)
	}
	if e.sess.has("acme") || e.sess.clears != 1 {
		t.Error("the session must be removed once the request was accepted")
	}
	// Stored: config (private, loadable), recorded binding, and the state ends bound.
	loaded, err := daemon.LoadConfig(e.dirs.Config)
	if err != nil || loaded.DeviceID != cfg.DeviceID || !strings.HasPrefix(loaded.KeyAccount, "k-") || loaded.KeyStore != daemon.KeyStoreFile {
		t.Fatalf("%+v %v", loaded, err)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{filepath.Join(e.dirs.Config, "config.json"), e.path(stateFile), e.path("bindings.json")} {
			if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("%s: %v %v", p, fi, err)
			}
		}
	}
	tr, err := binding.NewTracker(e.gw.rootPub, binding.NewFileStore(e.path("bindings.json")))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := tr.Version("acme", cfg.DeviceID); !ok || v != 1 {
		t.Errorf("binding version %d %v", v, ok)
	}
	if e.phase() != PhaseBound {
		t.Errorf("phase %s", e.phase())
	}
	// No secret anywhere the user or an operator reads: progress and logs carry ids, states and the public key fingerprint.
	for _, s := range []string{e.text(), logs.String()} {
		if strings.Contains(s, rq.poll) || strings.Contains(s, strings.Repeat("a", 64)) {
			t.Errorf("a secret reached output: %q", s)
		}
	}
	if !strings.Contains(e.text(), fingerprintHex(rq.key)) || !strings.Contains(logs.String(), "enrollment step") {
		t.Errorf("progress %q logs %q", e.text(), logs.String())
	}
	// Enrolled: a second run is refused and changes nothing; the daemon starts from what was left.
	if _, err := Enroll(bg, e.opts); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Errorf("second run: %v", err)
	}
	if _, err := Enroll(bg, e.resume()); !errors.Is(err, ErrAlreadyEnrolled) || e.keys.saves != 1 || e.gw.distinct() != 1 {
		t.Errorf("resume of a bound enrollment: %v saves=%d", err, e.keys.saves)
	}
	d, err := daemon.New(loaded, e.dirs, daemon.Deps{Log: logx.New(&bytes.Buffer{}), Keys: e.keys, Harden: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := d.Trust().Tracker.Version("acme", cfg.DeviceID); !ok || v != 1 {
		t.Errorf("daemon sees binding %d %v", v, ok)
	}
}

func TestEnrollWithAPodToken(t *testing.T) {
	e := newEnv(t)
	e.opts.Sessions, e.opts.Token = nil, podToken
	if _, err := Enroll(bg, e.opts); err != nil {
		t.Fatal(err)
	}
	for _, r := range e.gw.snapshot() {
		if r.token != podToken || r.auth != "" {
			t.Errorf("request %+v", r)
		}
	}
	// The token is never written down.
	for _, p := range []string{e.path(stateFile), filepath.Join(e.dirs.Config, "config.json")} {
		if b, _ := os.ReadFile(p); strings.Contains(string(b), podToken) {
			t.Errorf("%s holds the token", p)
		}
	}
}

func TestEnrollNeedsACredentialOnlyToSendTheRequest(t *testing.T) {
	e := newEnv(t)
	e.opts.Sessions = nil
	if _, err := Enroll(bg, e.opts); !errors.Is(err, ErrNeedCredential) {
		t.Fatalf("no store, no token: %v", err)
	}
	e.opts.Sessions = &memSessions{}
	if _, err := Enroll(bg, e.opts); !errors.Is(err, ErrNeedCredential) {
		t.Fatalf("not signed in: %v", err)
	}
	if e.phase() != PhaseRequesting || e.gw.distinct() != 0 {
		t.Fatalf("phase %s, requests %d", e.phase(), e.gw.distinct())
	}
	e.opts.Sessions = &memSessions{loadErr: errors.New("keychain locked")}
	if _, err := Enroll(bg, e.opts); err == nil || errors.Is(err, ErrNeedCredential) {
		t.Fatalf("a keychain failure is not 'not signed in': %v", err)
	}
	// Signing in and running again finishes it with the same key.
	if _, err := Enroll(bg, e.resume()); err != nil {
		t.Fatal(err)
	}
	if e.keys.saves != 1 || e.gw.distinct() != 1 {
		t.Errorf("saves=%d requests=%d", e.keys.saves, e.gw.distinct())
	}
}

// Every step boundary: the process stops there, and the next run finishes the
// enrollment with one key and one request, whatever the boundary.
func TestKilledAtEveryStepBoundaryResumesWithoutASecondKeyOrRequest(t *testing.T) {
	for _, tokenPath := range []bool{false, true} {
		for _, point := range CrashPoints {
			name := point
			if tokenPath {
				name += "/token"
			}
			t.Run(name, func(t *testing.T) {
				e := newEnv(t)
				if tokenPath {
					e.opts.Sessions, e.opts.Token = nil, podToken
				}
				stop := errors.New("killed")
				hit := false
				e.opts.Crash = func(p string) error {
					if p == point {
						hit = true
						return stop
					}
					return nil
				}
				if _, err := Enroll(bg, e.opts); !errors.Is(err, stop) || !hit {
					t.Fatalf("crash at %s: %v", point, err)
				}
				// The restart gets only what a restart has: no flags (a pod gets its token again from its environment).
				o := e.resume()
				if tokenPath {
					o.Sessions, o.Token = nil, podToken
				}
				res, err := Enroll(bg, o)
				if err != nil {
					t.Fatalf("resume after %s: %v", point, err)
				}
				if e.keys.saves != 1 || e.gw.distinct() != 1 || e.phase() != PhaseBound {
					t.Fatalf("saves=%d requests=%d phase=%s", e.keys.saves, e.gw.distinct(), e.phase())
				}
				if _, ok := e.gw.snapshot()[res.Config.DeviceID]; !ok {
					t.Error("the config names a device the gateway never saw")
				}
			})
		}
	}
}

func TestKilledAtEveryBoundaryInTurn(t *testing.T) {
	e := newEnv(t)
	fired := map[string]bool{}
	stop := errors.New("killed")
	e.opts.Crash = func(p string) error {
		if fired[p] {
			return nil
		}
		fired[p] = true
		return stop
	}
	o := e.opts
	runs := 0
	for {
		runs++
		if runs > len(CrashPoints)+2 {
			t.Fatal("not converging")
		}
		_, err := Enroll(bg, o)
		if err == nil {
			break
		}
		if !errors.Is(err, stop) {
			t.Fatalf("run %d: %v", runs, err)
		}
		o = e.resume()
		o.Crash = e.opts.Crash
	}
	if runs != len(CrashPoints)+1 || len(fired) != len(CrashPoints) || e.keys.saves != 1 || e.gw.distinct() != 1 {
		t.Errorf("runs=%d fired=%d saves=%d requests=%d", runs, len(fired), e.keys.saves, e.gw.distinct())
	}
}

func TestLostReplyIsRetriedWithoutASecondRequest(t *testing.T) {
	e := newEnv(t)
	var failed atomic.Bool
	e.gw.set(func(g *fakeGateway) {
		g.reqReply = func(id, poll string) (int, any) {
			if failed.CompareAndSwap(false, true) {
				return 500, nil
			}
			return 202, nil
		}
	})
	if _, err := Enroll(bg, e.opts); err == nil {
		t.Fatal("a failed request must fail the run")
	}
	if e.phase() != PhaseRequesting {
		t.Fatalf("phase %s", e.phase())
	}
	if _, err := Enroll(bg, e.resume()); err != nil {
		t.Fatal(err)
	}
	if e.gw.distinct() != 1 {
		t.Errorf("requests %d", e.gw.distinct())
	}
}

func TestResumeUsesTheSameRequestAndKey(t *testing.T) {
	e := newEnv(t)
	ctx, stop := context.WithCancel(bg)
	e.gw.set(func(g *fakeGateway) {
		g.status = func(string) (int, map[string]any) { stop(); return 200, map[string]any{"status": "pending"} }
	})
	if _, err := Enroll(ctx, e.opts); !errors.Is(err, context.Canceled) || errors.Is(err, ErrTimeout) {
		t.Fatalf("cancelled run: %v", err)
	}
	st, _ := loadState(e.dirs.State)
	first := *st
	e.gw.set(func(g *fakeGateway) { g.status = nil })
	if _, err := Enroll(bg, e.resume()); err != nil {
		t.Fatal(err)
	}
	st, _ = loadState(e.dirs.State)
	if st.ID != first.ID || st.Poll != first.Poll || !bytes.Equal(st.PublicKey, first.PublicKey) || e.keys.saves != 1 || e.gw.distinct() != 1 {
		t.Errorf("a resume changed the identity: %+v vs %+v", st, first)
	}
}

func TestTimeoutKeepsTheRequestForALaterRun(t *testing.T) {
	e := newEnv(t)
	e.gw.set(func(g *fakeGateway) { g.pending = 1 << 30 })
	e.opts.Timeout = 30 * time.Millisecond
	if _, err := Enroll(bg, e.opts); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
	if e.phase() != PhaseRequested {
		t.Fatalf("phase %s", e.phase())
	}
	e.gw.set(func(g *fakeGateway) { g.pending = 0 })
	if _, err := Enroll(bg, e.resume()); err != nil || e.gw.distinct() != 1 {
		t.Fatalf("%v requests=%d", err, e.gw.distinct())
	}
}

func TestRejectedAndExpiredRequestsAreAskedAgainWithTheSameKey(t *testing.T) {
	for name, tc := range map[string]struct {
		status func(string) (int, map[string]any)
		want   error
	}{
		"rejected": {func(string) (int, map[string]any) { return 200, map[string]any{"status": "rejected"} }, nil},
		"expired":  {func(string) (int, map[string]any) { return 404, nil }, ErrRequestExpired},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.gw.set(func(g *fakeGateway) { g.status = tc.status })
			_, err := Enroll(bg, e.opts)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v", err)
			}
			if e.phase() != PhaseKeyed || e.have(filepath.Join(e.dirs.Config, "config.json")) {
				t.Fatalf("phase %s", e.phase())
			}
			e.sess.Save("acme", "ps_acme."+strings.Repeat("a", 64))
			e.gw.set(func(g *fakeGateway) { g.status = nil })
			if _, err := Enroll(bg, e.resume()); err != nil {
				t.Fatal(err)
			}
			if e.keys.saves != 1 || e.gw.distinct() != 2 {
				t.Errorf("saves=%d requests=%d", e.keys.saves, e.gw.distinct())
			}
		})
	}
}

func TestAKeyIsCreatedOnceAndNeverSilentlyReplaced(t *testing.T) {
	e := newEnv(t)
	stop := errors.New("killed")
	e.opts.Crash = func(p string) error {
		if p == "requested" {
			return stop
		}
		return nil
	}
	if _, err := Enroll(bg, e.opts); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(e.path(stateFile))
	// The key vanishes (a wiped keychain): the run stops and changes nothing, rather than minting another identity.
	old := e.keys.key
	e.keys.forget()
	if _, err := Enroll(bg, e.resume()); !errors.Is(err, ErrKeyLost) {
		t.Fatalf("got %v", err)
	}
	// A different key appears under the same name.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	e.keys.key = other
	if _, err := Enroll(bg, e.resume()); !errors.Is(err, ErrKeyChanged) {
		t.Fatalf("got %v", err)
	}
	// A keychain that fails is a failure, not 'no key'.
	e.keys.loadErr = errors.New("locked")
	if _, err := Enroll(bg, e.resume()); err == nil || errors.Is(err, ErrKeyLost) {
		t.Fatalf("got %v", err)
	}
	e.keys.loadErr = nil
	after, _ := os.ReadFile(e.path(stateFile))
	if !bytes.Equal(before, after) || e.keys.saves != 1 || e.gw.distinct() != 1 {
		t.Fatal("a refused run changed state, key or requests")
	}
	e.keys.key = old
	if _, err := Enroll(bg, e.resume()); err != nil {
		t.Fatalf("with the key back: %v", err)
	}
}

func TestReplaceStartsANewIdentityAndReportsTheOldOnes(t *testing.T) {
	e := newEnv(t)
	first, err := Enroll(bg, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	e.keys.forget() // the device key is lost
	if _, err := Enroll(bg, e.resume()); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("without --replace: %v", err)
	}
	e.sess.Save("acme", "ps_acme."+strings.Repeat("b", 64))
	o := e.resume()
	o.Replace = true
	second, err := Enroll(bg, o)
	if err != nil {
		t.Fatal(err)
	}
	if second.Config.DeviceID == first.Config.DeviceID || second.Config.KeyAccount == first.Config.KeyAccount || e.keys.saves != 2 || e.gw.distinct() != 2 {
		t.Errorf("%+v %+v saves=%d", first.Config, second.Config, e.keys.saves)
	}
	if len(second.Replaced) != 1 || second.Replaced[0] != first.Config.DeviceID || !strings.Contains(e.text(), first.Config.DeviceID) {
		t.Errorf("replaced %v", second.Replaced)
	}
	// Replacing again lists both, once each.
	e.keys.forget()
	e.sess.Save("acme", "ps_acme."+strings.Repeat("c", 64))
	o = e.resume()
	o.Replace, o.Name, o.KeyStore = true, "new name", daemon.KeyStoreFile
	third, err := Enroll(bg, o)
	if err != nil || len(third.Replaced) != 2 {
		t.Fatalf("%v %v", third.Replaced, err)
	}
	if st, _ := loadState(e.dirs.State); st.Name != "new name" {
		t.Errorf("name %q", st.Name)
	}
}

func TestReplaceWhenStoppedHalfWayStillEndsWithoutTheOldConfig(t *testing.T) {
	e := newEnv(t)
	if _, err := Enroll(bg, e.opts); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(e.dirs.Config, "config.json")
	stop := errors.New("killed")
	o := e.resume()
	o.Replace = true
	o.Crash = func(p string) error {
		if p == "pinned" {
			return stop
		}
		return nil
	}
	e.keys.forget()
	if _, err := Enroll(bg, o); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	if !e.have(cfgPath) || e.phase() != PhasePinned {
		t.Fatal("the new state is saved before the old config goes")
	}
	e.sess.Save("acme", "ps_acme."+strings.Repeat("d", 64))
	res, err := Enroll(bg, e.resume())
	if err != nil || len(res.Replaced) != 1 {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestReplaceFromConfigOnlyAndWithNothing(t *testing.T) {
	e := newEnv(t)
	o := e.resume()
	o.Replace = true
	if _, err := Enroll(bg, o); !errors.Is(err, ErrNothingToReplace) {
		t.Fatalf("got %v", err)
	}
	// Only a config (no state file): its identity is replaced.
	first, err := Enroll(bg, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.path(stateFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll(bg, e.resume()); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("config without state: %v", err)
	}
	e.keys.forget()
	e.sess.Save("acme", "ps_acme."+strings.Repeat("e", 64))
	o = e.resume()
	o.Replace, o.Name = true, "again"
	res, err := Enroll(bg, o)
	if err != nil || len(res.Replaced) != 1 || res.Replaced[0] != first.Config.DeviceID {
		t.Fatalf("%v %+v", err, res)
	}
	// A damaged config cannot be replaced from.
	if err := os.WriteFile(filepath.Join(e.dirs.Config, "config.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(e.path(stateFile))
	if _, err := Enroll(bg, o); err == nil {
		t.Fatal("replaced from a damaged config")
	}
	// Bad replacement settings are refused.
	st := &state{Format: 1, Phase: PhasePinned, Gateway: e.gw.srv.URL, Tenant: "acme", RootPublicKey: e.gw.rootPub, Name: "n", KeyStore: daemon.KeyStoreFile, KeyAccount: "k-1"}
	if err := st.save(e.dirs.State); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Options){
		"key store": func(o *Options) { o.KeyStore = "cloud" },
		"entropy":   func(o *Options) { o.Rand = failRand{} },
		"name":      func(o *Options) { o.Name = "bad\nname" },
	} {
		o := e.resume()
		o.Replace = true
		mod(&o)
		if _, err := Enroll(bg, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReplaceDefaultsTheNameToTheHostWhenNoneWasEverSet(t *testing.T) {
	e := newEnv(t)
	cfg := daemon.Config{Format: 1, Tenant: "acme", DeviceID: "d1", GatewayURL: e.gw.srv.URL, RootPublicKey: e.gw.rootPub, KeyStore: daemon.KeyStoreFile, KeyAccount: "k-9"}
	if err := os.MkdirAll(e.dirs.Config, 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"format":1,"tenant":"acme","device_id":"d1","gateway_url":"` + e.gw.srv.URL + `","root_public_key":"` + b64(cfg.RootPublicKey) + `","key_store":"file"}`)
	if err := os.WriteFile(filepath.Join(e.dirs.Config, "config.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	o := e.resume()
	o.Replace = true
	if _, err := Enroll(bg, o); err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	for _, r := range e.gw.snapshot() {
		if r.name != host {
			t.Errorf("name %q, host %q", r.name, host)
		}
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestTrustOnFirstUseIsExplicit(t *testing.T) {
	fp := ""
	for name, tc := range map[string]struct {
		confirm func(string) bool
		want    error
	}{
		"confirmed":     {func(f string) bool { fp = f; return true }, nil},
		"declined":      {func(string) bool { return false }, ErrRootNotConfirmed},
		"nobody to ask": {nil, ErrRootNotConfirmed},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.opts.RootFingerprint, e.opts.TrustOnFirstUse, e.opts.Confirm = "", true, tc.confirm
			_, err := Enroll(bg, e.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v", err)
			}
			if tc.want != nil && (e.have(e.path(stateFile)) || e.keys.key != nil) {
				t.Error("an unconfirmed root left state or a key behind")
			}
			if !strings.Contains(e.text(), root.Fingerprint(e.gw.rootPub)) {
				t.Error("the user was not shown the fingerprint")
			}
		})
	}
	if fp == "" {
		t.Error("confirm was not called with the fingerprint")
	}
	e := newEnv(t)
	e.opts.RootFingerprint = ""
	if _, err := Enroll(bg, e.opts); !errors.Is(err, ErrRootRequired) {
		t.Errorf("neither: %v", err)
	}
}

func mustRoot(t *testing.T) ed25519.PublicKey { p, _, _ := ed25519.GenerateKey(rand.Reader); return p }

func TestAWrongRootFingerprintLeavesNothingBehind(t *testing.T) {
	e := newEnv(t)
	e.opts.RootFingerprint = strings.ToLower(root.Fingerprint(mustRoot(t)))
	if _, err := Enroll(bg, e.opts); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("got %v", err)
	}
	if e.have(e.path(stateFile)) || e.keys.key != nil || e.gw.distinct() != 0 {
		t.Error("state, key or request left behind")
	}
	// Typed any way, the right fingerprint is accepted.
	e.opts.RootFingerprint = strings.ToLower(strings.ReplaceAll(root.Fingerprint(e.gw.rootPub), "-", " "))
	if _, err := Enroll(bg, e.opts); err != nil {
		t.Fatal(err)
	}
}

func TestResumeRefusesOptionsForAnotherEnrollment(t *testing.T) {
	e := newEnv(t)
	e.gw.set(func(g *fakeGateway) { g.pending = 1 << 30 })
	e.opts.Timeout = 20 * time.Millisecond
	if _, err := Enroll(bg, e.opts); !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Options){
		"gateway": func(o *Options) { o.Gateway = "https://other.example.test" },
		"tenant":  func(o *Options) { o.Tenant = "other" },
	} {
		o := e.opts
		mod(&o)
		if _, err := Enroll(bg, o); err == nil || errors.Is(err, ErrTimeout) {
			t.Errorf("%s: %v", name, err)
		}
	}
	o := e.opts
	o.RootFingerprint = root.Fingerprint(mustRoot(t))
	if _, err := Enroll(bg, o); !errors.Is(err, ErrRootMismatch) {
		t.Errorf("fingerprint: %v", err)
	}
	o = e.opts
	o.Gateway += "/" // a trailing slash is the same gateway
	if _, err := Enroll(bg, o); !errors.Is(err, ErrTimeout) {
		t.Errorf("trailing slash: %v", err)
	}
}

func TestEnrollValidatesInput(t *testing.T) {
	long := strings.Repeat("n", 101)
	cases := map[string]struct {
		mod  func(*Options)
		want error
	}{
		"nothing at all":  {func(o *Options) { *o = Options{Dirs: o.Dirs} }, ErrNothingPending},
		"http gateway":    {func(o *Options) { o.Gateway = "http://gw.example.test" }, daemon.ErrConfig},
		"bad tenant":      {func(o *Options) { o.Tenant = "a b" }, daemon.ErrConfig},
		"bad key store":   {func(o *Options) { o.KeyStore = "cloud" }, daemon.ErrConfig},
		"long name":       {func(o *Options) { o.Name = long }, ErrBadName},
		"control in name": {func(o *Options) { o.Name = "a\x00b" }, ErrBadName},
		"no root":         {func(o *Options) { o.RootFingerprint = "" }, ErrRootRequired},
		"dashes only":     {func(o *Options) { o.RootFingerprint = "- -" }, ErrRootRequired},
		"no entropy":      {func(o *Options) { o.Rand = failRand{} }, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			tc.mod(&e.opts)
			_, err := Enroll(bg, e.opts)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if e.have(e.path(stateFile)) || e.keys.key != nil || e.gw.distinct() != 0 {
				t.Error("invalid input left state behind")
			}
		})
	}
}

func TestEnrollDefaultsTheNameToTheHostname(t *testing.T) {
	e := newEnv(t)
	e.opts.Name = ""
	if _, err := Enroll(bg, e.opts); err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	for _, r := range e.gw.snapshot() {
		if r.name != host || host == "" {
			t.Errorf("name %q, hostname %q", r.name, host)
		}
	}
}

func TestEnrollRefusesUnsoundGatewayReplies(t *testing.T) {
	t.Run("short root key", func(t *testing.T) {
		e := newEnv(t)
		e.gw.set(func(g *fakeGateway) {
			g.rootBody = func() any { return map[string]any{"root_public_key": []byte{1, 2, 3}} }
		})
		if _, err := Enroll(bg, e.opts); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("no root registered", func(t *testing.T) {
		e := newEnv(t)
		e.opts.Gateway = e.gw.srv.URL + "/nowhere"
		if _, err := Enroll(bg, e.opts); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("reply for another request", func(t *testing.T) {
		e := newEnv(t)
		e.gw.set(func(g *fakeGateway) { g.reqReply = func(string, string) (int, any) { return 202, nil } })
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/enroll/request" {
				w.WriteHeader(202)
				w.Write([]byte(`{"id":"` + strings.Repeat("0", 32) + `","poll":"x"}`))
				return
			}
			e.gw.serve(w, r)
		}))
		defer srv.Close()
		e.opts.Gateway = srv.URL
		if _, err := Enroll(bg, e.opts); !errors.Is(err, ErrBadReply) {
			t.Fatalf("got %v", err)
		}
		if e.phase() != PhaseRequesting {
			t.Errorf("phase %s", e.phase())
		}
	})
	t.Run("request refused", func(t *testing.T) {
		e := newEnv(t)
		e.sess.token["acme"] = "x"
		e.opts.Sessions = &memSessions{token: map[string]string{"acme": "ps_other.00"}}
		if _, err := Enroll(bg, e.opts); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestEnrollRejectsABindingForAnotherDeviceKeyOrRoot(t *testing.T) {
	other := mustRoot(t)
	for name, f := range map[string]func(e *env) func(string, []byte) *binding.Signed{
		"another key": func(e *env) func(string, []byte) *binding.Signed {
			return func(id string, _ []byte) *binding.Signed { return e.gw.signed(id, other, 1) }
		},
		"another device": func(e *env) func(string, []byte) *binding.Signed {
			return func(_ string, k []byte) *binding.Signed { return e.gw.signed("someone-else", k, 1) }
		},
		"not root-signed": func(e *env) func(string, []byte) *binding.Signed {
			return func(id string, k []byte) *binding.Signed {
				_, rogue, _ := ed25519.GenerateKey(rand.Reader)
				b, _ := binding.Sign(rogue, binding.Binding{Tenant: "acme", Owner: "a@b", DeviceID: id, SigningKey: k, Version: 1, NotAfter: time.Now().Add(time.Hour)})
				return b
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.gw.set(func(g *fakeGateway) { g.bind = f(e) })
			if _, err := Enroll(bg, e.opts); err == nil {
				t.Fatal("a binding the pinned root did not sign for this device and key was accepted")
			}
			if e.have(filepath.Join(e.dirs.Config, "config.json")) || e.phase() != PhaseRequested {
				t.Fatalf("config written or phase moved: %s", e.phase())
			}
		})
	}
}

func TestEnrollDoesNotFollowRedirects(t *testing.T) {
	var hit atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Add(1) }))
	defer elsewhere.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	e := newEnv(t)
	e.opts.Gateway = redir.URL
	e.opts.HTTP = nil
	if _, err := Enroll(bg, e.opts); err == nil || hit.Load() != 0 {
		t.Fatalf("a redirecting gateway was followed or accepted: %v hits=%d", err, hit.Load())
	}
}

func TestEnrollStopsWhileTheDaemonRunsOrAnotherEnrollRuns(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(e.dirs.State, 0o700); err != nil {
		t.Fatal(err)
	}
	release, err := daemon.LockState(e.dirs.State)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll(bg, e.opts); !errors.Is(err, daemon.ErrAlreadyRunning) {
		t.Fatalf("got %v", err)
	}
	release()
}

// Several processes (here goroutines, each with its own file descriptors, which
// the locks treat as separate holders) start the same enrollment: one request,
// one key, one config, whoever wins; the rest are refused.
func TestConcurrentEnrollsMakeOneIdentity(t *testing.T) {
	e := newEnv(t)
	var wg sync.WaitGroup
	results := make([]error, 6)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = Enroll(bg, e.opts)
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, daemon.ErrAlreadyRunning), errors.Is(err, ErrAlreadyEnrolled):
		default:
			t.Errorf("unexpected: %v", err)
		}
	}
	if ok != 1 || e.keys.saves != 1 || e.gw.distinct() != 1 || e.phase() != PhaseBound {
		t.Errorf("ok=%d saves=%d requests=%d phase=%s", ok, e.keys.saves, e.gw.distinct(), e.phase())
	}
}

func TestEnrollFailuresOfTheKeyAndTheDisk(t *testing.T) {
	t.Run("key store unavailable", func(t *testing.T) {
		e := newEnv(t)
		e.keys.loadErr = errors.New("keychain locked")
		if _, err := Enroll(bg, e.opts); err == nil || e.gw.distinct() != 0 {
			t.Fatal("a request was made without a device key")
		}
	})
	t.Run("key cannot be saved", func(t *testing.T) {
		e := newEnv(t)
		e.opts.Keys = failSave{}
		if _, err := Enroll(bg, e.opts); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("no entropy for the request id", func(t *testing.T) {
		e := newEnv(t)
		n := 0
		e.opts.Rand = failAfter(&n, 2) // account, key, then the request id fails
		if _, err := Enroll(bg, e.opts); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("no entropy for the poll secret", func(t *testing.T) {
		e := newEnv(t)
		n := 0
		e.opts.Rand = failAfter(&n, 3)
		if _, err := Enroll(bg, e.opts); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("directories unusable", func(t *testing.T) {
		e := newEnv(t)
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		o := e.opts
		o.Dirs = daemon.Dirs{Config: e.dirs.Config, State: filepath.Join(blocker, "state")}
		if _, err := Enroll(bg, o); err == nil {
			t.Fatal("accepted")
		}
		o.Dirs = daemon.Dirs{Config: filepath.Join(blocker, "cfg"), State: e.dirs.State}
		if _, err := Enroll(bg, o); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("corrupt binding store", func(t *testing.T) {
		e := newEnv(t)
		if err := os.MkdirAll(e.dirs.State, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(e.path("bindings.json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Enroll(bg, e.opts); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("config.json that exists without state is never overwritten", func(t *testing.T) {
		e := newEnv(t)
		if err := os.MkdirAll(e.dirs.Config, 0o700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(e.dirs.Config, "config.json")
		if err := os.WriteFile(p, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Enroll(bg, e.opts); !errors.Is(err, ErrAlreadyEnrolled) {
			t.Fatalf("got %v", err)
		}
		if b, _ := os.ReadFile(p); string(b) != "keep" {
			t.Error("config.json was overwritten")
		}
	})
}

// failAfter is a reader that serves n reads from crypto/rand and then fails.
type failReader struct {
	n    *int
	left int
}

func failAfter(n *int, left int) failReader { return failReader{n: n, left: left} }
func (f failReader) Read(p []byte) (int, error) {
	if *f.n >= f.left {
		return 0, errors.New("no entropy")
	}
	*f.n++
	return rand.Read(p)
}

// The disk refusing writes, made the same way on every OS: a file or a non-empty directory where the code needs
// a directory or a file it can replace. (No permission tricks, which behave differently per OS and per user.)
func TestEnrollWhenTheDiskRefusesWrites(t *testing.T) {
	t.Run("state path unusable", func(t *testing.T) {
		e := newEnv(t)
		if err := os.MkdirAll(filepath.Join(e.path(stateFile), "x"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Enroll(bg, e.opts); err == nil {
			t.Fatal("accepted")
		}
		if e.keys.key != nil || e.gw.distinct() != 0 {
			t.Error("a key or a request was made although nothing could be saved")
		}
	})
	t.Run("config cannot be written after the binding", func(t *testing.T) {
		e := newEnv(t)
		e.gw.set(func(g *fakeGateway) {
			g.bind = func(id string, key []byte) *binding.Signed {
				// Approval arrives, then the config directory is replaced by a file: nothing can be created in it.
				os.RemoveAll(e.dirs.Config)
				os.WriteFile(e.dirs.Config, nil, 0o600)
				return e.gw.signed(id, key, 1)
			}
		})
		if _, err := Enroll(bg, e.opts); err == nil {
			t.Fatal("accepted")
		}
		if e.phase() != PhaseApproved {
			t.Fatalf("phase %s: the next run must finish from approved", e.phase())
		}
		os.Remove(e.dirs.Config)
		e.gw.set(func(g *fakeGateway) { g.bind = nil })
		if _, err := Enroll(bg, e.resume()); err != nil || e.gw.distinct() != 1 || e.keys.saves != 1 {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a stale config cannot be removed", func(t *testing.T) {
		e := newEnv(t)
		if _, err := Enroll(bg, e.opts); err != nil {
			t.Fatal(err)
		}
		e.keys.forget()
		o := e.resume()
		o.Replace = true
		o.Crash = func(p string) error {
			if p == "pinned" { // the old config becomes a non-empty directory, which cannot be removed as a file
				cfg := filepath.Join(e.dirs.Config, "config.json")
				os.Remove(cfg)
				return os.MkdirAll(filepath.Join(cfg, "x"), 0o700)
			}
			return nil
		}
		if _, err := Enroll(bg, o); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestEnrollUsesTheConfiguredKeyStore(t *testing.T) {
	e := newEnv(t)
	e.opts.Keys = nil // the real file store, in the config directory
	res, err := Enroll(bg, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	ks, _, err := keystore.LoadOrCreate(daemon.KeyStoreFor(res.Config, e.dirs), nil)
	var rq *fakeReq
	for _, r := range e.gw.snapshot() {
		rq = r
	}
	if err != nil || !bytes.Equal(ks.Public().(ed25519.PublicKey), rq.key) {
		t.Errorf("the stored key is not the one that was enrolled: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.dirs.Config, "device.key")); err != nil {
		t.Error(err)
	}
	// An unset key store means the OS keychain (the keys double stands in; only the recorded choice is checked).
	e = newEnv(t)
	e.opts.KeyStore = ""
	if res, err = Enroll(bg, e.opts); err != nil || res.Config.KeyStore != daemon.KeyStoreKeychain {
		t.Errorf("%+v %v", res.Config, err)
	}
}

func TestLoadStateRejectsDamagedState(t *testing.T) {
	pub := make([]byte, 32)
	good := state{Format: 1, Phase: PhasePinned, Gateway: "https://gw.example.test", Tenant: "acme", RootPublicKey: pub, Name: "n", KeyStore: daemon.KeyStoreFile, KeyAccount: "k-1"}
	keyed := good
	keyed.Phase, keyed.PublicKey = PhaseKeyed, pub
	asked := keyed
	asked.Phase, asked.ID, asked.Poll = PhaseRequesting, strings.Repeat("a", 32), strings.Repeat("b", 48)
	mod := func(base state, f func(s *state)) string {
		s := base
		f(&s)
		b, _ := jsonMarshal(s)
		return string(b)
	}
	cases := map[string]string{
		"not json":          "{",
		"trailing":          mod(good, func(*state) {}) + "{}",
		"unknown field":     strings.Replace(mod(good, func(*state) {}), "{", `{"extra":1,`, 1),
		"format":            mod(good, func(s *state) { s.Format = 2 }),
		"gateway":           mod(good, func(s *state) { s.Gateway = "http://gw.example.test" }),
		"tenant":            mod(good, func(s *state) { s.Tenant = "a b" }),
		"account":           mod(good, func(s *state) { s.KeyAccount = "" }),
		"root":              mod(good, func(s *state) { s.RootPublicKey = []byte{1} }),
		"name":              mod(good, func(s *state) { s.Name = "" }),
		"key store":         mod(good, func(s *state) { s.KeyStore = "x" }),
		"phase":             mod(good, func(s *state) { s.Phase = "dreaming" }),
		"pinned with key":   mod(good, func(s *state) { s.PublicKey = pub }),
		"pinned with id":    mod(good, func(s *state) { s.ID = strings.Repeat("a", 32) }),
		"pinned with poll":  mod(good, func(s *state) { s.Poll = strings.Repeat("b", 48) }),
		"keyed without key": mod(keyed, func(s *state) { s.PublicKey = nil }),
		"keyed with id":     mod(keyed, func(s *state) { s.ID = strings.Repeat("a", 32) }),
		"keyed with poll":   mod(keyed, func(s *state) { s.Poll = strings.Repeat("b", 48) }),
		"asked without id":  mod(asked, func(s *state) { s.ID = "" }),
		"asked bad id":      mod(asked, func(s *state) { s.ID = "A" + strings.Repeat("a", 31) }),
		"asked short poll":  mod(asked, func(s *state) { s.Poll = "b" }),
		"asked without key": mod(asked, func(s *state) { s.PublicKey = nil }),
		"bad replaced id":   mod(asked, func(s *state) { s.Replaces = []string{"a/b"} }),
		"too many replaced": mod(asked, func(s *state) { s.Replaces = make([]string, maxReplaces+1) }),
		"too large":         strings.Repeat(" ", maxStateBytes+1),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadState(dir); !errors.Is(err, ErrBadState) {
				t.Fatalf("got %v", err)
			}
		})
	}
	for _, s := range []state{good, keyed, asked, {Format: 1, Phase: PhaseBound, Gateway: asked.Gateway, Tenant: "acme", RootPublicKey: pub, Name: "n", KeyStore: daemon.KeyStoreKeychain, KeyAccount: "k-1", PublicKey: pub, ID: asked.ID, Poll: asked.Poll, Replaces: []string{"d1"}}} {
		dir := t.TempDir()
		if err := s.save(dir); err != nil {
			t.Fatal(err)
		}
		if got, err := loadState(dir); err != nil || got.Phase != s.Phase {
			t.Fatalf("a valid %s state must load: %v", s.Phase, err)
		}
	}
	dir := t.TempDir()
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	if runtime.GOOS != "windows" {
		p := filepath.Join(dir, stateFile)
		if err := good.save(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadState(dir); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Errorf("a state file readable by others must be refused: %v", err)
		}
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := loadState(dir); err == nil && os.Geteuid() != 0 {
			t.Error("an unreadable file must fail")
		}
	}
}

func TestADamagedStateStopsTheRunAndIsNotChanged(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(e.dirs.State, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.path(stateFile), []byte(`{"format":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, replace := range []bool{false, true} {
		e.opts.Replace = replace
		if _, err := Enroll(bg, e.opts); !errors.Is(err, ErrBadState) {
			t.Fatalf("replace=%v: %v", replace, err)
		}
	}
	if b, _ := os.ReadFile(e.path(stateFile)); string(b) != `{"format":9}` || e.keys.key != nil || e.gw.distinct() != 0 {
		t.Error("a damaged state led to a change")
	}
}

func TestKeyStoreChoice(t *testing.T) {
	for in, want := range map[string]string{"": daemon.KeyStoreKeychain, "file": "file", "keychain": "keychain"} {
		if got, err := keyStoreChoice(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if _, err := keyStoreChoice("x"); err == nil {
		t.Error("accepted")
	}
}

func TestCrashPointsAreAllReachedOnAFullRun(t *testing.T) {
	e := newEnv(t)
	var seen []string
	e.opts.Crash = func(p string) error { seen = append(seen, p); return nil }
	if _, err := Enroll(bg, e.opts); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != strings.Join(CrashPoints, ",") {
		t.Errorf("reached %v, declared %v", seen, CrashPoints)
	}
}
