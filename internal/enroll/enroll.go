// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package enroll gets a device from "signed in" to "bound": it creates the
// device key once, requests approval, waits for the admin, verifies the
// root-signed binding against the pinned root, and stores binding and config.
//
// It is a persisted state machine (see the Phase constants). Every step saves
// before the next begins, every step is safe to repeat, and the request itself
// is idempotent at the gateway (the device chooses its id and poll secret and
// saves them before sending), so a process killed at any step boundary resumes
// without a second key and without a second request. CrashPoints names the
// boundaries; tests stop at each one.
//
// What it does not do: sign-in is Login (a separate step with its own
// session); the key store cannot delete, so the key of a replaced identity
// stays in the keychain, unreachable and unused.
package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/fsperm"
	"github.com/kalahroudi/parley/internal/keystore"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/root"
	"github.com/kalahroudi/parley/internal/trust"
)

var (
	// ErrAlreadyEnrolled means this device is enrolled. A lost device key is replaced explicitly (Options.Replace), never silently.
	ErrAlreadyEnrolled = errors.New("enroll: this device is already enrolled (use enroll --replace only if its key is lost)")
	// ErrNothingPending means there is no enrollment to resume and none was described.
	ErrNothingPending = errors.New("enroll: no enrollment in progress (give -gateway, -tenant and -root)")
	// ErrNothingToReplace means --replace found no identity to replace.
	ErrNothingToReplace = errors.New("enroll: nothing to replace")
	// ErrRootRequired means neither a root fingerprint nor trust-on-first-use was given.
	ErrRootRequired = errors.New("enroll: the root fingerprint from your admin is required (or --trust-on-first-use, which asks you to confirm it)")
	// ErrRootMismatch means the gateway's root key is not the one the admin shared.
	ErrRootMismatch = errors.New("enroll: the gateway's root key does not match the fingerprint you were given")
	// ErrRootNotConfirmed means trust-on-first-use was declined.
	ErrRootNotConfirmed = errors.New("enroll: the root fingerprint was not confirmed")
	// ErrNeedCredential means a request must be sent and the user has no session or pod token.
	ErrNeedCredential = errors.New("enroll: sign in first (parley-cli login) or give an enrollment token")
	// ErrKeyLost means the enrollment recorded a device key that the key store no longer has.
	ErrKeyLost = errors.New("enroll: the device key recorded for this enrollment is gone from the key store; nothing was changed. If it is really lost, run enroll --replace")
	// ErrKeyChanged means the key store holds a different key than the one recorded.
	ErrKeyChanged = errors.New("enroll: the key store holds a different device key than this enrollment recorded; nothing was changed")
	// ErrRequestExpired means the gateway no longer knows the request; the next run sends a new one.
	ErrRequestExpired = errors.New("enroll: the enrollment request expired or is unknown to the gateway; run enroll again")
	// ErrTimeout means the admin did not decide in time. The request stays; run enroll again to keep waiting.
	ErrTimeout = errors.New("enroll: timed out waiting for the admin; run parley-cli enroll again to keep waiting")
	// ErrBadReply means the gateway's answer was not what the request asked for.
	ErrBadReply = errors.New("enroll: the gateway's enrollment reply is not valid")
)

// CrashPoints are the step boundaries a Crash hook is called at, in order of a first run.
var CrashPoints = []string{"pinned", "key-created", "keyed", "request-chosen", "request-sent", "requested", "binding-recorded", "approved", "config-written"}

const defaultTimeout = time.Hour

func randHex(r io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// marshal is how files are encoded; tests replace it to fail the encoding step.
var marshal = func(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

// Options are the inputs of Enroll. On a first run Gateway, Tenant and the root
// (RootFingerprint, or TrustOnFirstUse with Confirm) are required, plus a
// credential: Token for a pod, else the session Login stored. When resuming they
// may all be empty (and are checked against the saved state if given).
type Options struct {
	Dirs            daemon.Dirs
	Gateway, Tenant string
	RootFingerprint string
	// TrustOnFirstUse accepts the root the gateway serves if Confirm says yes to its
	// fingerprint. It is explicit and shows the fingerprint: use the fingerprint
	// your admin sent whenever you have it.
	TrustOnFirstUse bool
	Confirm         func(fingerprint string) bool
	Name            string // device name shown to the admin (default: the host name)
	Token           string // a pod's single-use enrollment token; never stored
	Sessions        SessionStore
	KeyStore        string // daemon.KeyStoreKeychain (default) or daemon.KeyStoreFile
	// Replace abandons this device's identity (whose key is lost) and starts a new
	// one. The old device ids are reported for the admin to revoke.
	Replace  bool
	Poll     time.Duration
	Timeout  time.Duration // overall wait for the admin (default 1 hour)
	HTTP     *http.Client
	Now      func() time.Time
	Rand     io.Reader
	Keys     keystore.KeyStore // overrides KeyStore (tests)
	Log      *logx.Logger
	Progress func(string)
	// beforeSave is a test hook (tests in this package only): a non-nil result fails the save of that phase.
	beforeSave func(phase string) error
	// Crash is a test hook called at each of CrashPoints; a non-nil result stops the run there, as a kill would.
	Crash func(point string) error
}

// Result is what a finished enrollment reports.
type Result struct {
	Config daemon.Config
	// Replaced lists device ids this enrollment replaced; ask the admin to revoke them.
	Replaced []string
}

// Enroll runs (or resumes) the enrollment. It holds the daemon's instance lock,
// so it refuses to run beside a running parleyd or a second Enroll.
func Enroll(ctx context.Context, o Options) (Result, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	if o.HTTP == nil {
		o.HTTP = newHTTP()
	}
	if o.Progress == nil {
		o.Progress = func(string) {}
	}
	if o.Log == nil {
		o.Log = logx.New(io.Discard)
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	for _, dir := range []string{o.Dirs.Config, o.Dirs.State} {
		if err := fsperm.EnsureDir(dir); err != nil {
			return Result{}, err
		}
	}
	release, err := daemon.LockState(o.Dirs.State)
	if err != nil {
		return Result{}, err
	}
	defer release()
	en := &run{Options: o, cfgPath: filepath.Join(o.Dirs.Config, "config.json")}
	return en.run(ctx)
}

type run struct {
	Options
	cfgPath string
	st      *state
	signer  ed25519.PrivateKey
}

func (en *run) crash(point string) error {
	if en.Crash == nil {
		return nil
	}
	return en.Crash(point)
}

func (en *run) enter(phase string) error {
	en.st.Phase = phase
	logStep(en.Log, en.st.Tenant, phase)
	if en.beforeSave != nil {
		if err := en.beforeSave(phase); err != nil {
			return err
		}
	}
	return en.st.save(en.Dirs.State)
}

// logStep records a step: ids and a phase name, nothing else. (A free function with plain parameters, so the
// log scan can see no payload name near the call.)
func logStep(l *logx.Logger, tenant, phase string) {
	l.Info("enrollment step", logx.ID("tenant", tenant), logx.ID("state", phase))
}

func (en *run) configExists() bool {
	_, err := os.Stat(en.cfgPath)
	return err == nil
}

func (en *run) run(ctx context.Context) (Result, error) {
	st, err := en.begin(ctx)
	if err != nil {
		return Result{}, err
	}
	en.st = st
	if st.Phase != PhaseApproved && en.configExists() {
		// Left by an earlier identity (a replace that stopped half way); it must not outlive its state.
		if err := os.Remove(en.cfgPath); err != nil {
			return Result{}, err
		}
	}
	defer func() { keystore.Zero(en.signer) }()
	if err := en.ensureKey(); err != nil {
		return Result{}, err
	}
	pub := en.signer.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	en.Progress("device key fingerprint (compare with the admin's list): " + hex.EncodeToString(sum[:]))

	if st.Phase == PhaseKeyed {
		if st.ID, err = randHex(en.Rand, 16); err != nil {
			return Result{}, err
		}
		if st.Poll, err = randHex(en.Rand, 24); err != nil {
			return Result{}, err
		}
		if err := en.enter(PhaseRequesting); err != nil {
			return Result{}, err
		}
		if err := en.crash("request-chosen"); err != nil {
			return Result{}, err
		}
	}
	cl := &trust.Client{BaseURL: st.Gateway, HTTP: en.HTTP}
	if st.Phase == PhaseRequesting {
		if err := en.sendRequest(ctx, cl, pub); err != nil {
			return Result{}, err
		}
	}
	if st.Phase == PhaseRequested {
		if err := en.await(ctx, cl, pub); err != nil {
			return Result{}, err
		}
	}
	// Each step above ends in the next phase, so this is PhaseApproved whichever phase the run began in.
	cfg, err := en.writeConfig()
	if err != nil {
		return Result{}, err
	}
	return Result{Config: cfg, Replaced: st.Replaces}, nil
}

// begin finds the state to run: the saved one, a new one, or the replacement for a lost identity.
func (en *run) begin(ctx context.Context) (*state, error) {
	st, err := loadState(en.Dirs.State)
	if errors.Is(err, os.ErrNotExist) {
		st, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	if en.Replace {
		return en.replace(st)
	}
	if st == nil {
		if en.configExists() {
			return nil, ErrAlreadyEnrolled // enrolled by other means: never touched
		}
		return en.start(ctx)
	}
	if st.Phase == PhaseBound {
		return nil, ErrAlreadyEnrolled
	}
	return st, st.matches(en.Options)
}

// start validates a first run, pins the root and saves the first state.
func (en *run) start(ctx context.Context) (*state, error) {
	gw := strings.TrimRight(en.Gateway, "/")
	if gw == "" && en.Tenant == "" && en.RootFingerprint == "" && !en.TrustOnFirstUse {
		return nil, ErrNothingPending
	}
	st, err := en.newState(ctx, gw)
	if err != nil {
		return nil, err
	}
	if err := en.enterNew(st); err != nil {
		return nil, err
	}
	return st, nil
}

func (en *run) enterNew(st *state) error {
	en.st = st
	if err := en.enter(PhasePinned); err != nil {
		return err
	}
	return en.crash("pinned")
}

func (en *run) newState(ctx context.Context, gw string) (*state, error) {
	if err := daemon.ValidGatewayURL(gw); err != nil {
		return nil, err
	}
	if !daemon.ValidID(en.Tenant) {
		return nil, fmt.Errorf("%w: tenant must be 1-64 characters of A-Z a-z 0-9 - _", daemon.ErrConfig)
	}
	name := en.Name
	if name == "" {
		name, _ = os.Hostname()
	}
	if err := ValidName(name); err != nil {
		return nil, err
	}
	ks, err := keyStoreChoice(en.KeyStore)
	if err != nil {
		return nil, err
	}
	if normFingerprint(en.RootFingerprint) == "" && !en.TrustOnFirstUse {
		return nil, ErrRootRequired
	}
	rk, err := (&trust.Client{BaseURL: gw, HTTP: en.HTTP}).FetchRoot(ctx, en.Tenant)
	if err != nil {
		return nil, err
	}
	fp := root.Fingerprint(rk)
	if normFingerprint(en.RootFingerprint) != "" {
		if normFingerprint(fp) != normFingerprint(en.RootFingerprint) {
			return nil, ErrRootMismatch
		}
	} else {
		// Trust on first use is explicit: the user sees the fingerprint and must confirm it.
		en.Progress("The gateway presents the root key with fingerprint " + fp)
		if en.Confirm == nil || !en.Confirm(fp) {
			return nil, ErrRootNotConfirmed
		}
	}
	acct, err := randHex(en.Rand, 8)
	if err != nil {
		return nil, err
	}
	return &state{Format: stateFormat, Gateway: gw, Tenant: en.Tenant, RootPublicKey: rk, Name: name, KeyStore: ks, KeyAccount: "k-" + acct}, nil
}

func keyStoreChoice(s string) (string, error) {
	switch s {
	case "":
		return daemon.KeyStoreKeychain, nil
	case daemon.KeyStoreKeychain, daemon.KeyStoreFile:
		return s, nil
	}
	return "", fmt.Errorf("%w: key_store must be keychain or file", daemon.ErrConfig)
}

// matches rejects options that describe a different enrollment than the saved one.
func (s *state) matches(o Options) error {
	if o.Gateway != "" && strings.TrimRight(o.Gateway, "/") != s.Gateway || o.Tenant != "" && o.Tenant != s.Tenant {
		return fmt.Errorf("enroll: a different enrollment (another gateway or tenant) is in progress; finish it with parley-cli enroll")
	}
	if o.RootFingerprint != "" && normFingerprint(o.RootFingerprint) != normFingerprint(root.Fingerprint(s.RootPublicKey)) {
		return ErrRootMismatch
	}
	return nil
}

// replace abandons the saved identity and starts over from the same pinned root.
// The new state is saved before the old config goes, so a stop in between leaves
// a state that the next run finishes.
func (en *run) replace(old *state) (*state, error) {
	var ids []string
	var base *state
	if old != nil {
		base = old
		if old.ID != "" {
			ids = append(ids, old.ID)
		}
		ids = append(ids, old.Replaces...)
	} else if en.configExists() {
		cfg, err := daemon.LoadConfig(en.Dirs.Config)
		if err != nil {
			return nil, err
		}
		base = &state{Format: stateFormat, Gateway: cfg.GatewayURL, Tenant: cfg.Tenant, RootPublicKey: cfg.RootPublicKey, KeyStore: cfg.KeyStore}
		ids = append(ids, cfg.DeviceID)
	} else {
		return nil, ErrNothingToReplace
	}
	acct, err := randHex(en.Rand, 8)
	if err != nil {
		return nil, err
	}
	st := &state{
		Format: stateFormat, Phase: PhasePinned, Gateway: base.Gateway, Tenant: base.Tenant, RootPublicKey: base.RootPublicKey,
		Name: base.Name, KeyStore: base.KeyStore, KeyAccount: "k-" + acct, Replaces: dedupe(ids),
	}
	if en.Name != "" {
		st.Name = en.Name
	}
	if st.Name == "" {
		st.Name, _ = os.Hostname()
	}
	if en.KeyStore != "" {
		if st.KeyStore, err = keyStoreChoice(en.KeyStore); err != nil {
			return nil, err
		}
	}
	if !st.valid() {
		return nil, ErrBadState
	}
	if err := en.enterNew(st); err != nil {
		return nil, err
	}
	en.Progress("Replacing this device's identity. Ask your admin to revoke: " + strings.Join(st.Replaces, ", "))
	return st, nil
}

func dedupe(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func (en *run) keys() keystore.KeyStore {
	if en.Keys != nil {
		return en.Keys
	}
	return daemon.KeyStoreFor(daemon.Config{KeyStore: en.st.KeyStore, KeyAccount: en.st.KeyAccount}, en.Dirs)
}

// ensureKey creates the device key exactly once. Before the key is recorded it
// may be created here; once recorded (phase keyed or later) a missing or
// different key is an error, never a new key.
func (en *run) ensureKey() error {
	ks := en.keys()
	if en.st.Phase == PhasePinned {
		signer, _, err := keystore.LoadOrCreate(ks, en.Rand)
		if err != nil {
			return err
		}
		en.signer = signer
		if err := en.crash("key-created"); err != nil {
			return err
		}
		en.st.PublicKey = append([]byte(nil), signer.Public().(ed25519.PublicKey)...)
		if err := en.enter(PhaseKeyed); err != nil {
			return err
		}
		return en.crash("keyed")
	}
	signer, err := ks.Load()
	if errors.Is(err, keystore.ErrNoKey) {
		return ErrKeyLost
	}
	if err != nil {
		return err
	}
	if !signer.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(en.st.PublicKey)) {
		keystore.Zero(signer)
		return ErrKeyChanged
	}
	en.signer = signer
	return nil
}

// sendRequest sends the (idempotent) enrollment request. The credential is the
// pod token if given, else the stored session; the session is removed once the
// gateway has accepted the request, because it has done its one job.
func (en *run) sendRequest(ctx context.Context, cl *trust.Client, pub ed25519.PublicKey) error {
	st := en.st
	req := trust.EnrollRequest{Name: st.Name, Key: pub, ID: st.ID, Poll: st.Poll}
	var session bool
	if en.Token != "" {
		req.Tenant, req.Token = st.Tenant, en.Token
	} else if en.Sessions != nil {
		tok, err := en.Sessions.Load(st.Tenant)
		if err != nil {
			if errors.Is(err, ErrNoSession) {
				return ErrNeedCredential
			}
			return err
		}
		cl.Auth, session = "Bearer "+tok, true
	} else {
		return ErrNeedCredential
	}
	id, poll, err := cl.Request(ctx, req)
	if err != nil {
		return err
	}
	if id != st.ID || poll != st.Poll {
		return ErrBadReply
	}
	if err := en.crash("request-sent"); err != nil {
		return err
	}
	if err := en.enter(PhaseRequested); err != nil {
		return err
	}
	if session {
		if err := en.Sessions.Clear(st.Tenant); err != nil {
			en.Progress("warning: the sign-in session could not be removed from the keychain; it expires on its own")
		}
	}
	en.Progress("enrollment requested; waiting for the admin to approve this device")
	return en.crash("requested")
}

// await waits for the decision (with backoff, bounded by Timeout) and records the
// binding the pinned root signed.
func (en *run) await(ctx context.Context, cl *trust.Client, pub ed25519.PublicKey) error {
	st := en.st
	tracker, err := binding.NewTracker(ed25519.PublicKey(st.RootPublicKey), binding.NewFileStore(filepath.Join(en.Dirs.State, "bindings.json")))
	if err != nil {
		return err
	}
	td := &trust.Daemon{Tracker: tracker, Client: cl, Tenant: st.Tenant}
	wctx, cancel := context.WithTimeout(ctx, en.Timeout)
	defer cancel()
	if _, err := td.Await(wctx, st.ID, st.Poll, pub, en.Poll, en.Now); err != nil {
		if errors.Is(err, trust.ErrNotFound) || errors.Is(err, trust.ErrRejected) {
			// The request is over: forget it and keep the key, so the next run asks again with the same device key.
			if errors.Is(err, trust.ErrNotFound) {
				err = ErrRequestExpired
			}
			st.ID, st.Poll = "", ""
			return errors.Join(err, en.enter(PhaseKeyed))
		}
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return ErrTimeout
		}
		return err
	}
	if err := en.crash("binding-recorded"); err != nil {
		return err
	}
	if err := en.enter(PhaseApproved); err != nil {
		return err
	}
	return en.crash("approved")
}

// writeConfig stores the config (root, gateway, device id) atomically and marks the enrollment bound.
func (en *run) writeConfig() (daemon.Config, error) {
	st := en.st
	cfg := daemon.Config{
		Format: daemon.ConfigFormat, Tenant: st.Tenant, DeviceID: st.ID, GatewayURL: st.Gateway,
		RootPublicKey: st.RootPublicKey, KeyStore: st.KeyStore, KeyAccount: st.KeyAccount,
	}
	data, err := marshal(cfg)
	if err != nil {
		return daemon.Config{}, err
	}
	if err := fsperm.WriteAtomic(en.cfgPath, data); err != nil {
		return daemon.Config{}, err
	}
	if err := en.crash("config-written"); err != nil {
		return daemon.Config{}, err
	}
	return cfg, en.enter(PhaseBound)
}

// normFingerprint compares fingerprints however they were typed: any case, with or without the group dashes and spaces.
func normFingerprint(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s))
}
