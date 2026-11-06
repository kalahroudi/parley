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
	"sync"
	"sync/atomic"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/botproc"
	"github.com/kalahroudi/parley/internal/caller"
	"github.com/kalahroudi/parley/internal/connect"
	"github.com/kalahroudi/parley/internal/fsperm"
	"github.com/kalahroudi/parley/internal/keystore"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/pipeline"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/revocation"
	"github.com/kalahroudi/parley/internal/root"
	"github.com/kalahroudi/parley/internal/supervisor"
	"github.com/kalahroudi/parley/internal/trust"
	"github.com/kalahroudi/parley/internal/tunnel"
)

// ErrAlreadyRunning means another parleyd holds this device's instance lock.
var ErrAlreadyRunning = errors.New("daemon: another parleyd is already running for this configuration")

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
	Keys keystore.KeyStore
	Rand io.Reader
	// Harden is called first; a failure stops startup. Default: prekey.Harden
	// (no core dumps, no Go tracebacks).
	Harden func() error
	// TunnelConfig returns the tunnel settings (URL and a way to get a device
	// connect token) each time the tunnel component (re)starts. Default: the
	// configured gateway, with a token earned by signing its challenge with the
	// device key (internal/connect).
	TunnelConfig func(ctx context.Context, signer ed25519.PrivateKey) (tunnel.Config, error)
	// OnEvent, if set, sees every tunnel event, in order, before the pipeline
	// does (a tap for tests and tracing). It must not block for long.
	OnEvent func(tunnel.Event)
	HTTP    *http.Client
	// Directory finds a peer's current root-signed binding (it is only a source:
	// the pipeline verifies every binding against the pinned root and the rollback
	// store). Nil means the configured gateway's directory (caller.Directory.Binding).
	Directory func(ctx context.Context, device string) (*binding.Signed, error)
	// Allow is the owner allowlist for callers into this device's bots; OnInbound
	// is the bot; OnUpdate gets the progress of tasks this device sent. With both
	// nil the built-in test bot runs (see testbot.go), unless Config.DisableTestBot
	// is set; with only one of them nil no bot runs here and every prekey request
	// is refused.
	Allow     func(owner string) bool
	OnInbound func(pipeline.Inbound)
	OnUpdate  func(pipeline.Update)
	// AllowUnlockedMemory lets the pipeline run when the OS will not lock its key
	// memory in RAM (a container without the capability). Prekeys could then be
	// swapped out; the default refuses to start the pipeline instead.
	AllowUnlockedMemory bool
	// Supervisor tuning (tests); zero values use the defaults. SweepEvery is how
	// often the pipeline ends tasks that ran out of time.
	MinBackoff, ShutdownTimeout, SweepEvery time.Duration
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
	sup     *supervisor.Supervisor
	srv     *localsock.Server
	started time.Time

	nodeMu sync.Mutex
	node   *pipeline.Node
	pool   *prekey.Pool
	caller *caller.Service
	host   *bot.Host // the test bot's host, or nil
	tun    atomic.Pointer[tunnel.Client]
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
	if deps.SweepEvery <= 0 {
		deps.SweepEvery = sweepEvery
	}
	if deps.Rand == nil {
		deps.Rand = rand.Reader
	}
	if deps.Harden == nil {
		deps.Harden = prekey.Harden
	}
	if deps.OnEvent == nil {
		deps.OnEvent = func(tunnel.Event) {}
	}
	if err := deps.Harden(); err != nil {
		return nil, fmt.Errorf("daemon: hardening failed: %w", err)
	}
	for _, dir := range []string{dirs.Config, dirs.State} {
		if err := fsperm.EnsureDir(dir); err != nil {
			return nil, err
		}
	}
	ks := deps.Keys
	if ks == nil {
		ks = KeyStoreFor(cfg, dirs)
	}
	signer, created, err := keystore.LoadOrCreateLocked(ks, deps.Rand, instanceLock(dirs.State))
	if err != nil {
		return nil, err
	}
	if created {
		deps.Log.Info("device key created", logx.ID("device", cfg.DeviceID))
	}
	rootPub := ed25519.PublicKey(cfg.RootPublicKey)
	tracker, err := binding.NewTracker(rootPub, binding.NewFileStore(filepath.Join(dirs.State, "bindings.json")))
	if err != nil {
		keystore.Zero(signer)
		return nil, err
	}
	guard, err := revocation.NewGuard(rootPub, cfg.Tenant, revocation.NewFileStore(filepath.Join(dirs.State, "revocations.json")), deps.Now())
	if err != nil {
		keystore.Zero(signer)
		return nil, err
	}
	if deps.TunnelConfig == nil {
		deps.TunnelConfig = connectTunnel(cfg, deps.HTTP, func() (uint64, bool) { return tracker.Version(cfg.Tenant, cfg.DeviceID) })
	}
	d := &Daemon{
		cfg: cfg, dirs: dirs, deps: deps, signer: signer, tracker: tracker, guard: guard,
		trust: &trust.Daemon{
			Tracker: tracker, Guard: guard, Tenant: cfg.Tenant,
			Client: &trust.Client{BaseURL: cfg.GatewayURL, HTTP: deps.HTTP},
		},
		sup: &supervisor.Supervisor{Log: deps.Log, MinBackoff: deps.MinBackoff, ShutdownTimeout: deps.ShutdownTimeout},
	}
	d.srv = &localsock.Server{Log: deps.Log, UID: os.Geteuid(), Methods: map[string]localsock.Method{"status": d.status},
		// Approving or denying a task is the owner's alone: a process that belongs to a bot this daemon started is refused (see botproc).
		Sensitive: map[string]bool{"approve": true, "deny": true}, Guard: botGuard(botproc.Default)}
	d.initCaller()
	d.initTestBot()
	return d, nil
}

// ErrNotEnrolled means the daemon holds no binding for itself yet, so it has nothing to prove to the gateway.
var ErrNotEnrolled = errors.New("daemon: no binding recorded for this device (not enrolled yet)")

// connectTunnel is the default TunnelConfig: the tunnel dials the configured gateway and, before every connection
// attempt, proves possession of the device key (the one in the keystore) for the binding version the daemon has
// recorded, and gets a fresh single-use connect token. A gateway that refuses the device (not bound, revoked,
// binding expired) stops the tunnel with a refusal and the supervisor retries later with backoff, so a revoked
// device does not hammer the gateway; a spent rate limit or a network error is retried inside the tunnel with its
// jittered backoff; a daemon with no binding yet waits the same way.
func connectTunnel(cfg Config, hc *http.Client, version func() (uint64, bool)) func(context.Context, ed25519.PrivateKey) (tunnel.Config, error) {
	return func(_ context.Context, signer ed25519.PrivateKey) (tunnel.Config, error) {
		url, err := connect.TunnelURL(cfg.GatewayURL)
		if err != nil {
			return tunnel.Config{}, err
		}
		cl := &connect.Client{BaseURL: cfg.GatewayURL, Tenant: cfg.Tenant, Device: cfg.DeviceID, HTTP: hc}
		return tunnel.Config{URL: url, TokenSource: func(ctx context.Context) (string, error) {
			v, ok := version()
			if !ok {
				return "", ErrNotEnrolled
			}
			tok, err := cl.Token(ctx, signer, v, connect.ScopeConnect)
			if errors.Is(err, connect.ErrRefused) {
				return "", fmt.Errorf("%w: %w", tunnel.ErrRefused, err)
			}
			return tok.Secret, err
		}}, nil
	}
}

func KeyStoreFor(cfg Config, dirs Dirs) keystore.KeyStore {
	if cfg.KeyStore == KeyStoreFile {
		return keystore.FileStore{Dir: dirs.Config}
	}
	return &keystore.KeychainStore{Account: cfg.KeyAccount, KR: osKeyring{}}
}

// botGuard allows a caller unless it belongs to a running bot, or cannot be told apart from one.
func botGuard(r *botproc.Registry) func(pid int) error {
	return func(pid int) error {
		if isBot, err := r.Owns(pid); err != nil || isBot {
			return errBotCaller
		}
		return nil
	}
}

var errBotCaller = errors.New("daemon: the caller belongs to a bot")

// Handle registers a local socket method. Call it before Run.
func (d *Daemon) Handle(name string, m localsock.Method) { d.srv.Methods[name] = m }

// SigningKey is the device's Ed25519 key. It stays in this process.
func (d *Daemon) SigningKey() ed25519.PrivateKey { return d.signer }

// Trust is the binding tracker and revocation guard pinned to the root.
func (d *Daemon) Trust() *trust.Daemon { return d.trust }

// StatusInfo is what the "status" method returns: metadata only.
type StatusInfo struct {
	Tenant      string                       `json:"tenant"`
	Device      string                       `json:"device"`
	RootPrint   string                       `json:"root_fingerprint"`
	Uptime      int64                        `json:"uptime_seconds"`
	Components  []supervisor.ComponentStatus `json:"components"`
	Revocations string                       `json:"revocation_warning"` // fixed text from trust.Daemon.Warning, or ""
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
// the key and release the instance lock. It returns supervisor.ErrShutdownTimeout if a
// component would not stop.
func (d *Daemon) Run(ctx context.Context) error {
	defer keystore.Zero(d.signer)
	defer d.caller.Close() // after closeNode: no update can arrive once the pipeline is closed
	defer d.closeNode()    // before the key is zeroed (defers run last in, first out): the pipeline signs with it until then
	defer d.closeHost()    // before the pipeline closes: the bot stops answering first
	release, err := LockState(d.dirs.State)
	if err != nil {
		return err
	}
	defer release()
	ln, err := localsock.Listen(d.dirs.SocketPath())
	if err != nil {
		return err
	}
	defer os.Remove(d.dirs.SocketPath())
	d.started = d.deps.Now()
	d.deps.Log.Info("parleyd started", logx.ID("tenant", d.cfg.Tenant), logx.ID("device", d.cfg.DeviceID))

	sctx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	served := make(chan struct{})
	go func() { d.srv.Serve(sctx, ln); close(served) }()

	err = d.sup.Run(ctx, d.components()...)
	stopServing()
	<-served
	d.deps.Log.Info("parleyd stopped")
	return err
}

func (d *Daemon) closeHost() {
	if d.host != nil {
		d.host.Close()
	}
}

// instanceLock is LockState for a state directory, as a function value.
func instanceLock(stateDir string) func() (func(), error) {
	return func() (func(), error) { return LockState(stateDir) }
}

// LockState takes the per-device instance lock; the lock file lives in the
// state directory and the kernel frees it when the process exits.
func LockState(stateDir string) (func(), error) {
	release, err := fsperm.Lock(filepath.Join(stateDir, "parleyd.lock"))
	if errors.Is(err, fsperm.ErrLocked) {
		return nil, ErrAlreadyRunning
	}
	return release, err
}

func (d *Daemon) components() []supervisor.Component {
	return []supervisor.Component{
		{Name: "tunnel", Run: d.runTunnel, MaxBackoff: 5 * time.Minute},
		{Name: "revocations", Run: d.runRefresh},
		{Name: "sweep", Run: d.runSweep},
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
	d.tun.Store(c)
	defer d.tun.CompareAndSwap(c, nil)
	// Run closes Events when it returns, so ranging ends the drain and waiting for
	// it means every event received has been handed on, in order, before we return.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for ev := range c.Events() {
			d.handleEvent(ctx, ev)
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
