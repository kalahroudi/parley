// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/kalahroudi/parley/internal/fsperm"
	"github.com/kalahroudi/parley/internal/keystore"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/revocation"
	"github.com/kalahroudi/parley/internal/root"
	"github.com/kalahroudi/parley/internal/supervisor"
	"github.com/kalahroudi/parley/internal/tunnel"
)

type env struct {
	cfg  Config
	dirs Dirs
	log  *syncBuf
	root ed25519.PrivateKey
	gw   *httptest.Server
	revs func() *revocation.Signed // what the fake gateway serves
}

// newEnv builds a config pointing at a fake gateway that serves a signed
// revocation list, with the file key store (the OS keychain is tested apart).
func newEnv(t *testing.T) *env {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e := &env{log: &syncBuf{}, root: priv}
	dir := filepath.Join(shortTemp(t), "p")
	e.dirs = Dirs{Config: dir, State: dir}
	first, err := revocation.Next(priv, "t1", nil, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.revs = func() *revocation.Signed { return first }
	e.gw = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") && strings.Contains(r.URL.Path, "revocation") {
			json.NewEncoder(w).Encode(e.revs())
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(e.gw.Close)
	e.cfg = Config{Format: 1, Tenant: "t1", DeviceID: "dev-1", GatewayURL: e.gw.URL, RootPublicKey: pub, KeyStore: KeyStoreFile}
	if _, err := ParseConfig(mustJSON(e.cfg)); err != nil {
		t.Fatal(err)
	}
	return e
}

func mustJSON(c Config) []byte { b, _ := json.Marshal(c); return b }

func (e *env) deps() Deps {
	return Deps{Log: logx.New(e.log), Harden: func() error { return nil }, MinBackoff: time.Millisecond, ShutdownTimeout: 5 * time.Second}
}

type running struct {
	d      *Daemon
	cancel context.CancelFunc
	done   chan error
}

func (e *env) start(t *testing.T, mod func(*Deps)) *running {
	t.Helper()
	deps := e.deps()
	if mod != nil {
		mod(&deps)
	}
	d, err := New(e.cfg, e.dirs, deps)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{d: d, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- d.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-r.done })
	waitUp(t, e)
	return r
}

// waitUp waits until the daemon answers on its socket (the file appears at bind,
// slightly before listen).
func waitUp(t *testing.T, e *env) {
	t.Helper()
	waitFor(t, "daemon to answer", func() bool {
		r, err := localsock.Call(context.Background(), e.dirs.SocketPath(), "status", nil)
		return err == nil && r.OK
	})
}

func (r *running) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		r.done <- err
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop")
		return nil
	}
}

func status(t *testing.T, e *env) StatusInfo {
	t.Helper()
	r, err := localsock.Call(context.Background(), e.dirs.SocketPath(), "status", nil)
	if err != nil || !r.OK {
		t.Fatalf("status: %+v %v", r, err)
	}
	var s StatusInfo
	if err := json.Unmarshal(r.Result, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDaemonLifecycle(t *testing.T) {
	e := newEnv(t)
	r := e.start(t, nil)
	s := status(t, e)
	if s.Tenant != "t1" || s.Device != "dev-1" || s.RootPrint != root.Fingerprint(ed25519.PublicKey(e.cfg.RootPublicKey)) {
		t.Errorf("status identity: %+v", s)
	}
	if len(s.Components) != 2 || s.Components[0].Name != "tunnel" || s.Components[1].Name != "revocations" {
		t.Errorf("components: %+v", s.Components)
	}
	// The revocation refresh fetches the fake gateway's list and persists it.
	waitFor(t, "revocation list fetched", func() bool { return status(t, e).Revocations == "" })
	if _, err := os.Stat(filepath.Join(e.dirs.State, "revocations.json")); err != nil {
		t.Errorf("revocation list not persisted: %v", err)
	}
	if len(r.d.SigningKey()) != ed25519.PrivateKeySize || r.d.Trust() == nil {
		t.Error("accessors")
	}
	key := append(ed25519.PrivateKey(nil), r.d.SigningKey()...)

	if err := r.stop(t); err != nil {
		t.Fatalf("clean shutdown returned %v", err)
	}
	if _, err := os.Lstat(e.dirs.SocketPath()); !os.IsNotExist(err) {
		t.Errorf("socket file left behind: %v", err)
	}
	if bytes.Equal(r.d.signer, key) || !bytes.Equal(r.d.signer, make([]byte, len(key))) {
		t.Error("the in-memory signing key was not wiped on shutdown")
	}
	out := e.log.String()
	if !strings.Contains(out, "parleyd started") || !strings.Contains(out, "parleyd stopped") {
		t.Errorf("lifecycle not logged: %s", out)
	}

	// The key persists: a second run is the same device.
	r2 := e.start(t, nil)
	if !bytes.Equal(r2.d.signer, key) {
		t.Error("the device key changed across restarts")
	}
}

func TestRevocationStalenessSurvivesRestart(t *testing.T) {
	e := newEnv(t)
	r := e.start(t, nil)
	waitFor(t, "list", func() bool { return status(t, e).Revocations == "" })
	r.stop(t)
	// Restart with the gateway down: the persisted list is still held.
	e.gw.Close()
	e.start(t, nil)
	if w := status(t, e).Revocations; w != "" {
		t.Errorf("a fresh persisted list must be loaded on start, warning: %q", w)
	}
}

func TestStatusShowsMissingRevocationList(t *testing.T) {
	e := newEnv(t)
	e.gw.Close() // the gateway is unreachable from the start
	e.start(t, nil)
	if w := status(t, e).Revocations; !strings.Contains(w, "no revocation list") {
		t.Errorf("warning = %q", w)
	}
	waitFor(t, "refresh failure logged", func() bool { return strings.Contains(e.log.String(), "revocation refresh failed") })
}

func TestSecondInstanceRefused(t *testing.T) {
	e := newEnv(t)
	e.start(t, nil)
	d2, err := New(e.cfg, e.dirs, e.deps())
	if err != nil {
		t.Fatal(err)
	}
	if err := d2.Run(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("second instance: %v", err)
	}
	if _, err := os.Lstat(e.dirs.SocketPath()); err != nil {
		t.Error("the second instance removed the first one's socket")
	}
	if status(t, e).Tenant != "t1" {
		t.Error("first instance no longer answers")
	}
}

func TestNewFailsClosed(t *testing.T) {
	e := newEnv(t)
	base := e.deps()
	cases := map[string]func(*Deps){
		"no logger":      func(d *Deps) { d.Log = nil },
		"harden fails":   func(d *Deps) { d.Harden = func() error { return errors.New("no") } },
		"entropy":        func(d *Deps) { d.Rand = failRand{} },
		"key store down": func(d *Deps) { d.Keys = failSave{} },
	}
	for name, mod := range cases {
		deps := base
		mod(&deps)
		if _, err := New(e.cfg, e.dirs, deps); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
	// A corrupt device key stops startup and is left alone.
	os.MkdirAll(e.dirs.Config, 0o700)
	kp := filepath.Join(e.dirs.Config, "device.key")
	os.WriteFile(kp, []byte("junk"), 0o600)
	if _, err := New(e.cfg, e.dirs, base); !errors.Is(err, keystore.ErrKeyCorrupt) {
		t.Errorf("corrupt key: %v", err)
	}
	if b, _ := os.ReadFile(kp); string(b) != "junk" {
		t.Error("the corrupt key was replaced")
	}
	os.Remove(kp)
	// A corrupt rollback store stops startup too (it must not reset to empty).
	os.WriteFile(filepath.Join(e.dirs.State, "bindings.json"), []byte("{"), 0o600)
	if _, err := New(e.cfg, e.dirs, base); err == nil {
		t.Error("corrupt binding store accepted")
	}
	os.Remove(filepath.Join(e.dirs.State, "bindings.json"))
	os.WriteFile(filepath.Join(e.dirs.State, "revocations.json"), []byte("{"), 0o600)
	if _, err := New(e.cfg, e.dirs, base); err == nil {
		t.Error("corrupt revocation store accepted")
	}
	os.Remove(filepath.Join(e.dirs.State, "revocations.json"))
	// A directory that is not private stops startup.
	if runtime.GOOS != "windows" {
		os.Chmod(e.dirs.State, 0o755)
		if _, err := New(e.cfg, e.dirs, base); err == nil {
			t.Error("a world-readable state directory was accepted")
		}
	}
}

func TestRunFailsWhenInstanceLockCannotBeOpened(t *testing.T) {
	e := newEnv(t)
	d, err := New(e.cfg, e.dirs, e.deps())
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(e.dirs.State, "parleyd.lock")
	os.Remove(lockPath)       // first-run key creation in New leaves one behind
	os.Mkdir(lockPath, 0o700) // a directory where the lock file belongs
	if err := d.Run(context.Background()); err == nil || errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("want a lock error, got %v", err)
	}
}

func TestNewUsesKeychainByDefault(t *testing.T) {
	e := newEnv(t)
	e.cfg.KeyStore = KeyStoreKeychain
	if _, ok := keyStoreFor(e.cfg, e.dirs).(*keystore.KeychainStore); !ok {
		t.Error("keychain is the default key store")
	}
	e.cfg.KeyStore = KeyStoreFile
	if _, ok := keyStoreFor(e.cfg, e.dirs).(keystore.FileStore); !ok {
		t.Error("file key store on request")
	}
}

func TestRunFailsOnBadSocketPath(t *testing.T) {
	e := newEnv(t)
	e.dirs.State = filepath.Join(e.dirs.State, strings.Repeat("a", localsock.MaxPath))
	d, err := New(e.cfg, e.dirs, e.deps())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Run(context.Background()); err == nil {
		t.Error("over-long socket path accepted")
	}
}

func TestHandleRegistersMethods(t *testing.T) {
	e := newEnv(t)
	d, err := New(e.cfg, e.dirs, e.deps())
	if err != nil {
		t.Fatal(err)
	}
	d.Handle("ping", func(context.Context, json.RawMessage) (any, error) { return "pong", nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitUp(t, e)
	if r, err := localsock.Call(context.Background(), e.dirs.SocketPath(), "ping", nil); err != nil || string(r.Result) != `"pong"` {
		t.Errorf("%+v %v", r, err)
	}
}

func TestTunnelWaitsForConnectToken(t *testing.T) {
	e := newEnv(t)
	e.start(t, nil) // the default TunnelConfig returns ErrNoConnectToken
	waitFor(t, "tunnel in backoff with restarts", func() bool {
		for _, c := range status(t, e).Components {
			if c.Name == "tunnel" && c.Restarts >= 2 && c.State == supervisor.StateBackoff {
				return true
			}
		}
		return false
	})
	if status(t, e).Components[1].State != supervisor.StateRunning {
		t.Error("a missing connect token must not stop the other components")
	}
}

// fakeTunnelGateway accepts one connection, completes the hello/welcome
// handshake and pushes the given events.
func fakeTunnelGateway(t *testing.T, events []string, seen chan<- string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx := r.Context()
		if _, _, err := c.Read(ctx); err != nil {
			return
		}
		c.Write(ctx, websocket.MessageText, []byte(`{"t":"welcome","session":"s1","resumed":false,"rx_seq":0,"heartbeat_ms":1000}`))
		for i, body := range events {
			b, _ := json.Marshal(map[string]any{"t": "event", "seq": i + 1, "body": body})
			c.Write(ctx, websocket.MessageText, b)
		}
		<-ctx.Done()
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTunnelEventsReachTheHandlerInOrder(t *testing.T) {
	e := newEnv(t)
	seen := make(chan string, 4)
	gw := fakeTunnelGateway(t, []string{"a", "b", "c"}, seen)
	var mu sync.Mutex
	var got []string
	var gotKey ed25519.PrivateKey
	r := e.start(t, func(d *Deps) {
		d.TunnelConfig = func(_ context.Context, k ed25519.PrivateKey) (tunnel.Config, error) {
			gotKey = k
			return tunnel.Config{URL: "ws" + strings.TrimPrefix(gw.URL, "http"), Token: "tok-1"}, nil
		}
		d.OnEvent = func(ev tunnel.Event) { mu.Lock(); got = append(got, ev.Body); mu.Unlock() }
	})
	if h := <-seen; h != "Bearer tok-1" {
		t.Errorf("tunnel auth header = %q", h)
	}
	waitFor(t, "three events", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 3 })
	mu.Lock()
	if strings.Join(got, "") != "abc" {
		t.Errorf("events out of order: %v", got)
	}
	mu.Unlock()
	if !gotKey.Equal(r.d.SigningKey()) {
		t.Error("TunnelConfig did not receive the device key")
	}
	if err := r.stop(t); err != nil {
		t.Errorf("shutdown with a live tunnel: %v", err)
	}
}

func TestTunnelFatalErrorIsRetriedBySupervisor(t *testing.T) {
	e := newEnv(t)
	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusUnauthorized) }))
	defer refuse.Close()
	e.start(t, func(d *Deps) {
		d.TunnelConfig = func(context.Context, ed25519.PrivateKey) (tunnel.Config, error) {
			return tunnel.Config{URL: "ws" + strings.TrimPrefix(refuse.URL, "http"), Token: "bad"}, nil
		}
	})
	waitFor(t, "restart after refused credentials", func() bool { return status(t, e).Components[0].Restarts >= 2 })
}

func TestRunInStopsOnShutdownBeforeTheTokenArrives(t *testing.T) {
	e := newEnv(t)
	r := e.start(t, nil)
	if err := r.stop(t); err != nil {
		t.Errorf("stop while the tunnel is waiting for a token: %v", err)
	}
}

func TestNewLogger(t *testing.T) {
	for lvl, hidden := range map[string]string{"debug": "", "info": "dbg", "warn": "inf", "error": "wrn"} {
		var b bytes.Buffer
		l := NewLogger(&b, lvl)
		l.Info("inf")
		l.Warn("wrn")
		l.Error("err")
		if hidden != "" && strings.Contains(b.String(), hidden) {
			t.Errorf("%s: %q should be hidden: %s", lvl, hidden, b.String())
		}
		if !strings.Contains(b.String(), "err") {
			t.Errorf("%s: error not logged", lvl)
		}
	}
	var b bytes.Buffer
	NewLogger(&b, "").Info("default")
	if b.Len() == 0 {
		t.Error("default level must log info")
	}
}

// Two daemons starting together on a first run must not both mint a key: the
// keychain keeps only the last write, so one would run under an identity that is
// stored nowhere.
func TestFirstRunKeyCreationNeedsTheInstanceLock(t *testing.T) {
	e := newEnv(t)
	if err := fsperm.EnsureDir(e.dirs.State); err != nil {
		t.Fatal(err)
	}
	release, err := lockState(e.dirs.State) // another daemon is starting
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(e.cfg, e.dirs, e.deps()); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("first run under a held lock: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.dirs.Config, "device.key")); err == nil {
		t.Error("a device key was created without the lock")
	}
	release()
	if _, err := New(e.cfg, e.dirs, e.deps()); err != nil {
		t.Fatal(err)
	}
	// With the key in place a running daemon's lock does not block New.
	release, err = lockState(e.dirs.State)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := New(e.cfg, e.dirs, e.deps()); err != nil {
		t.Errorf("New with a key present: %v", err)
	}
}
