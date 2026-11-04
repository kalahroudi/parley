// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/revocation"
	"github.com/kalahroudi/parley/internal/root"
	"github.com/kalahroudi/parley/internal/trust"
	"github.com/kalahroudi/parley/internal/tunnel"
)

// ErrAlreadyRunning means another parleyd holds this device's instance lock.
var ErrAlreadyRunning = errors.New("daemon: another parleyd is already running for this configuration")

// ErrNoConnectToken is what the default tunnel config returns: the gateway
// issues device connect tokens in task T415, and until then /v1/connect is closed.
var ErrNoConnectToken = errors.New("daemon: no device connect token available yet")

// Dirs are the daemon's directories. Config holds config.json and, for the
// file key store, device.key; State holds the rollback stores, the instance
// lock and the socket.
type Dirs struct{ Config, State string }

// DefaultDirs returns $PARLEY_HOME for both when it is set (several daemons on
// one machine, as in the dev harness), else <user config dir>/parley.
func DefaultDirs(getenv func(string) string, userConfigDir func() (string, error)) (Dirs, error) {
	if h := getenv("PARLEY_HOME"); h != "" {
		// Absolute, so the socket path can never be read as a Linux abstract name ("@...").
		abs, err := filepath.Abs(h)
		if err != nil {
			return Dirs{}, fmt.Errorf("daemon: PARLEY_HOME: %w", err)
		}
		return Dirs{Config: abs, State: abs}, nil
	}
	d, err := userConfigDir()
	if err != nil {
		return Dirs{}, fmt.Errorf("daemon: no user config directory: %w", err)
	}
	p := filepath.Join(d, "parley")
	return Dirs{Config: p, State: p}, nil
}

// SocketPath is where parley-cli finds the daemon.
func (d Dirs) SocketPath() string { return filepath.Join(d.State, "parleyd.sock") }

// Deps are the seams between the core and the rest of the daemon. Zero values
// pick the production behaviour.
type Deps struct {
	Log *logx.Logger // required
	Now func() time.Time
	// Keys overrides the key store chosen by Config.KeyStore.
	Keys KeyStore
	Rand io.Reader
	// Harden is called first; a failure stops startup. Default: prekey.Harden
	// (no core dumps, no Go tracebacks).
	Harden func() error
	// TunnelConfig returns the tunnel settings (URL and device connect token)
	// each time the tunnel component (re)starts. Default: ErrNoConnectToken.
	TunnelConfig func(ctx context.Context, signer ed25519.PrivateKey) (tunnel.Config, error)
	// OnEvent receives every tunnel event, in order. Required whenever
	// TunnelConfig can succeed: the tunnel stalls if nobody drains it.
	OnEvent func(tunnel.Event)
	HTTP    *http.Client
	// Supervisor tuning (tests); zero values use the defaults.
	MinBackoff, ShutdownTimeout time.Duration
}

// Daemon is one parleyd. Create it with New, register Methods with Handle,
// then call Run.
type Daemon struct {
	cfg    Config
	dirs   Dirs
	deps   Deps
	signer ed25519.PrivateKey

	tracker *binding.Tracker
	guard   *revocation.Guard
	trust   *trust.Daemon
	sup     *Supervisor
	srv     *server
	started time.Time
}

// New validates the environment and opens everything that must be sound before
// the daemon serves anything: the private directories, the device key (created
// on first run), and the pinned-root rollback stores. Any failure is fatal:
// there is no degraded mode.
func New(cfg Config, dirs Dirs, deps Deps) (*Daemon, error) {
	if deps.Log == nil {
		return nil, errors.New("daemon: a logger is required")
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Rand == nil {
		deps.Rand = rand.Reader
	}
	if deps.Harden == nil {
		deps.Harden = prekey.Harden
	}
	if deps.TunnelConfig == nil {
		deps.TunnelConfig = noConnectToken
	}
	if deps.OnEvent == nil {
		deps.OnEvent = func(tunnel.Event) {}
	}
	if err := deps.Harden(); err != nil {
		return nil, fmt.Errorf("daemon: hardening failed: %w", err)
	}
	for _, dir := range []string{dirs.Config, dirs.State} {
		if err := ensurePrivateDir(dir); err != nil {
			return nil, err
		}
	}
	ks := deps.Keys
	if ks == nil {
		ks = keyStoreFor(cfg, dirs)
	}
	signer, created, err := loadOrCreateOnce(ks, deps.Rand, dirs.State)
	if err != nil {
		return nil, err
	}
	if created {
		deps.Log.Info("device key created", logx.ID("device", cfg.DeviceID))
	}
	rootPub := ed25519.PublicKey(cfg.RootPublicKey)
	tracker, err := binding.NewTracker(rootPub, binding.NewFileStore(filepath.Join(dirs.State, "bindings.json")))
	if err != nil {
		zero(signer)
		return nil, err
	}
	guard, err := revocation.NewGuard(rootPub, cfg.Tenant, revocation.NewFileStore(filepath.Join(dirs.State, "revocations.json")), deps.Now())
	if err != nil {
		zero(signer)
		return nil, err
	}
	d := &Daemon{
		cfg: cfg, dirs: dirs, deps: deps, signer: signer, tracker: tracker, guard: guard,
		trust: &trust.Daemon{
			Tracker: tracker, Guard: guard, Tenant: cfg.Tenant,
			Client: &trust.Client{BaseURL: cfg.GatewayURL, HTTP: deps.HTTP},
		},
		sup: &Supervisor{Log: deps.Log, MinBackoff: deps.MinBackoff, ShutdownTimeout: deps.ShutdownTimeout},
	}
	d.srv = &server{log: deps.Log, uid: os.Geteuid(), methods: map[string]Method{"status": d.status}}
	return d, nil
}

// noConnectToken is the default TunnelConfig until the gateway issues connect tokens (T415).
func noConnectToken(context.Context, ed25519.PrivateKey) (tunnel.Config, error) {
	return tunnel.Config{}, ErrNoConnectToken
}

func keyStoreFor(cfg Config, dirs Dirs) KeyStore {
	if cfg.KeyStore == KeyStoreFile {
		return FileKeyStore{Dir: dirs.Config}
	}
	return NewKeychainStore(cfg.DeviceID)
}

// Handle registers a local socket method. Call it before Run.
func (d *Daemon) Handle(name string, m Method) { d.srv.methods[name] = m }

// SigningKey is the device's Ed25519 key. It stays in this process.
func (d *Daemon) SigningKey() ed25519.PrivateKey { return d.signer }

// Trust is the binding tracker and revocation guard pinned to the root.
func (d *Daemon) Trust() *trust.Daemon { return d.trust }

// StatusInfo is what the "status" method returns: metadata only.
type StatusInfo struct {
	Tenant      string            `json:"tenant"`
	Device      string            `json:"device"`
	RootPrint   string            `json:"root_fingerprint"`
	Uptime      int64             `json:"uptime_seconds"`
	Components  []ComponentStatus `json:"components"`
	Revocations string            `json:"revocation_warning"` // fixed text from trust.Daemon.Warning, or ""
}

func (d *Daemon) status(context.Context, json.RawMessage) (any, error) {
	now := d.deps.Now()
	return StatusInfo{
		Tenant: d.cfg.Tenant, Device: d.cfg.DeviceID,
		RootPrint:  root.Fingerprint(ed25519.PublicKey(d.cfg.RootPublicKey)),
		Uptime:     int64(now.Sub(d.started) / time.Second),
		Components: d.sup.Status(), Revocations: d.trust.Warning(now),
	}, nil
}

// Run serves the local socket and the supervised components until ctx ends,
// then shuts down in order: stop accepting and close local connections, stop
// the components (tunnel first closes its socket), remove the socket file, wipe
// the key and release the instance lock. It returns ErrShutdownTimeout if a
// component would not stop.
func (d *Daemon) Run(ctx context.Context) error {
	defer zero(d.signer)
	release, err := lockState(d.dirs.State)
	if err != nil {
		return err
	}
	defer release()
	ln, err := listenSocket(d.dirs.SocketPath())
	if err != nil {
		return err
	}
	defer os.Remove(d.dirs.SocketPath())
	d.started = d.deps.Now()
	d.deps.Log.Info("parleyd started", logx.ID("tenant", d.cfg.Tenant), logx.ID("device", d.cfg.DeviceID))

	sctx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	served := make(chan struct{})
	go func() { d.srv.serve(sctx, ln); close(served) }()

	err = d.sup.Run(ctx, d.components()...)
	stopServing()
	<-served
	d.deps.Log.Info("parleyd stopped")
	return err
}

// loadOrCreateOnce is LoadOrCreate with the instance lock held around the
// creation. Two daemons starting together on a first run would otherwise both
// find no key and both mint one, and the keychain keeps only the last write:
// the loser would run under an identity that is stored nowhere. The common case
// (key present) takes no lock, so a running daemon never blocks a second New.
func loadOrCreateOnce(ks KeyStore, rnd io.Reader, stateDir string) (ed25519.PrivateKey, bool, error) {
	if key, err := ks.Load(); !errors.Is(err, ErrNoKey) {
		return key, false, err
	}
	release, err := lockState(stateDir)
	if err != nil {
		return nil, false, err
	}
	defer release()
	return LoadOrCreate(ks, rnd)
}

// lockState takes the per-device instance lock; the lock file lives in the
// state directory and the kernel frees it when the process exits.
func lockState(stateDir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(stateDir, "parleyd.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("daemon: open instance lock: %w", err)
	}
	ok, err := tryLockFile(f)
	if err != nil || !ok {
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("daemon: instance lock: %w", err)
		}
		return nil, ErrAlreadyRunning
	}
	return func() { f.Close() }, nil
}

func (d *Daemon) components() []Component {
	return []Component{
		{Name: "tunnel", Run: d.runTunnel, MaxBackoff: 5 * time.Minute},
		{Name: "revocations", Run: d.runRefresh},
	}
}

// runTunnel asks for a fresh config on each start (connect tokens are
// short-lived) and runs the tunnel client, passing its events on in order.
func (d *Daemon) runTunnel(ctx context.Context) error {
	cfg, err := d.deps.TunnelConfig(ctx, d.signer)
	if err != nil {
		return err
	}
	c := tunnel.New(cfg)
	// Run closes Events when it returns, so ranging ends the drain and waiting for
	// it means every event received has been handed on, in order, before we return.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for ev := range c.Events() {
			d.deps.OnEvent(ev)
		}
	}()
	err = c.Run(ctx)
	<-drained
	return err
}

// runRefresh keeps the revocation list fresh. A failed fetch is logged (no
// text) and the held list keeps ageing toward the warning and refusal.
func (d *Daemon) runRefresh(ctx context.Context) error {
	d.trust.RunRefresh(ctx, d.cfg.RefreshEvery(), d.deps.Now, func(error) {
		d.deps.Log.Warn("revocation refresh failed", logx.ID("tenant", d.cfg.Tenant))
	})
	return nil
}

// NewLogger builds the daemon's redacting logger for the configured level.
func NewLogger(w io.Writer, level string) *logx.Logger {
	return logx.NewLevel(w, logx.ParseLevel(level))
}
