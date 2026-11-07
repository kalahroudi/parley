// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package signer is the local signer service: the only process that holds the
// tenant root key on behalf of the admin dashboard. It exposes a small HTTP API
// on a loopback listener protected by a per-session secret. The root key and
// the recovery code never leave it, except the recovery code once, in the reply
// to root init. Signing goes through internal/root, internal/binding,
// internal/revocation and internal/trust.
package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kalahroudi/parley/internal/revocation"
	"github.com/kalahroudi/parley/internal/root"
	"github.com/kalahroudi/parley/internal/trust"
)

// ErrNotLoopback is returned when asked to listen on a non-loopback address.
var ErrNotLoopback = errors.New("signer: listen address must be loopback")

const maxBody = 64 << 10

// Request limits per window. A person clicking in the dashboard stays far below them; a script that holds the
// session secret cannot use the signer as a signing oracle at machine speed or grind recovery codes.
const (
	rateWindow  = time.Minute
	maxRequests = 120
	maxRecovery = 5 // failed attempts per window
)

// limiterNow is the clock of the rate limiter, apart from Server.Clock, which tests pin to a fixed time.
var limiterNow = time.Now

// limiter admits at most max calls in each fixed window.
type limiter struct {
	mu    sync.Mutex
	start time.Time
	n     int
}

// roll starts a new window once the old one has run out; the caller holds mu.
func (l *limiter) roll() {
	if now := limiterNow(); now.Sub(l.start) >= rateWindow {
		l.start, l.n = now, 0
	}
}

// allow counts a call and reports whether it is within max.
func (l *limiter) allow(max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll()
	l.n++
	return l.n <= max
}

// open reports whether fewer than max calls were counted in this window, without counting.
func (l *limiter) open(max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll()
	return l.n < max
}

// hit counts one call.
func (l *limiter) hit() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.roll()
	l.n++
}

// Seams so tests can force failures that crypto/rand and the file system do
// not produce on demand.
var (
	newRoot    = root.New
	createFile = func(path string) (io.WriteCloser, error) {
		return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	}
)

// KeyStore is the root store plus read-back, which only the signer needs.
type KeyStore interface {
	root.Store
	Load() (ed25519.PrivateKey, error)
}

// Server is the signer's HTTP handler.
type Server struct {
	Store KeyStore
	// Revocations holds the newest list this signer issued. Without it a caller could present an old list
	// as the base and have the signer re-issue the chain minus later revocations, un-revoking devices.
	Revocations revocation.Store
	BackupPath  string           // where root init writes the encrypted backup
	Secret      string           // per-session bearer secret
	Clock       func() time.Time // defaults to time.Now
	host        string           // the only accepted Host header value
	all         limiter          // every admitted request
	failures    limiter          // failed recovery attempts
	issueMu     sync.Mutex       // one revocation list is issued at a time
}

// NewSecret returns a fresh random per-session secret (128 bits).
func NewSecret() string { return rand.Text() }

// Listen opens a TCP listener on a loopback address (use "127.0.0.1:0" for a
// free port) and pins the handler to that address.
func (s *Server) Listen(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		return nil, ErrNotLoopback
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s.host = l.Addr().String()
	return l, nil
}

func (s *Server) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

// Handler returns the API. Every request must come from a loopback peer, carry
// the pinned Host (DNS rebinding), carry no Origin (browsers always send one on
// cross-site requests), and present the session secret.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/root", s.rootStatus)
	mux.HandleFunc("POST /v1/root/init", s.rootInit)
	mux.HandleFunc("POST /v1/root/recover", s.rootRecover)
	mux.HandleFunc("POST /v1/bindings/sign", s.signBinding)
	mux.HandleFunc("POST /v1/revocations/sign", s.signRevocation)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.admit(r) {
			reply(w, http.StatusForbidden, errBody("forbidden"))
			return
		}
		if !s.all.allow(maxRequests) {
			w.Header().Set("Retry-After", "60")
			reply(w, http.StatusTooManyRequests, errBody("too many requests"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) admit(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !ap.Addr().Unmap().IsLoopback() {
		return false
	}
	if s.host == "" || r.Host != s.host || r.Header.Get("Origin") != "" {
		return false
	}
	got := []byte(r.Header.Get("Authorization"))
	want := []byte("Bearer " + s.Secret)
	return s.Secret != "" && subtle.ConstantTimeCompare(got, want) == 1
}

type errResp struct {
	Error string `json:"error"`
}

func errBody(msg string) errResp { return errResp{msg} }

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		reply(w, http.StatusBadRequest, errBody("bad request"))
		return false
	}
	return true
}

// key loads the root key, replying 409 when there is none.
func (s *Server) key(w http.ResponseWriter) (ed25519.PrivateKey, bool) {
	k, err := s.Store.Load()
	if errors.Is(err, root.ErrNoRoot) {
		reply(w, http.StatusConflict, errBody("no root key; run root init or recovery first"))
		return nil, false
	}
	if err != nil {
		reply(w, http.StatusInternalServerError, errBody("cannot read the root key"))
		return nil, false
	}
	return k, true
}

type statusResp struct {
	Exists      bool   `json:"exists"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func (s *Server) rootStatus(w http.ResponseWriter, r *http.Request) {
	k, err := s.Store.Load()
	if errors.Is(err, root.ErrNoRoot) {
		reply(w, http.StatusOK, statusResp{})
		return
	}
	if err != nil {
		reply(w, http.StatusInternalServerError, errBody("cannot read the root key"))
		return
	}
	reply(w, http.StatusOK, statusResp{true, root.Fingerprint(k.Public().(ed25519.PublicKey))})
}

type initResp struct {
	Fingerprint  string `json:"fingerprint"`
	RecoveryCode string `json:"recovery_code"` // shown once
}

// rootInit is idempotent in the safe direction: an existing root is never
// overwritten (409), and a retry does not mint a second recovery code.
func (s *Server) rootInit(w http.ResponseWriter, r *http.Request) {
	if exists, err := s.Store.Exists(); err != nil {
		reply(w, http.StatusInternalServerError, errBody("cannot check for a root key"))
		return
	} else if exists {
		reply(w, http.StatusConflict, errBody(root.ErrExists.Error()))
		return
	}
	nr, err := newRoot()
	if err != nil {
		reply(w, http.StatusInternalServerError, errBody("cannot create a root key"))
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.BackupPath), 0o700); err != nil {
		reply(w, http.StatusInternalServerError, errBody("cannot write the backup"))
		return
	}
	// O_EXCL: never overwrite (or later delete) a backup that belongs to another root.
	if err := writeNew(s.BackupPath, nr.Backup); err != nil {
		if errors.Is(err, os.ErrExist) {
			reply(w, http.StatusConflict, errBody("a root backup file already exists on this device"))
		} else {
			reply(w, http.StatusInternalServerError, errBody("cannot write the backup"))
		}
		return
	}
	if err := s.Store.Save(nr.Private); err != nil {
		os.Remove(s.BackupPath)
		if errors.Is(err, root.ErrExists) {
			reply(w, http.StatusConflict, errBody(root.ErrExists.Error()))
		} else {
			reply(w, http.StatusInternalServerError, errBody("cannot save the root key"))
		}
		return
	}
	reply(w, http.StatusOK, initResp{nr.Fingerprint, nr.RecoveryCode})
}

func writeNew(path string, data []byte) error {
	f, err := createFile(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

type recoverReq struct {
	RecoveryCode string `json:"recovery_code"`
	Backup       []byte `json:"backup,omitempty"` // defaults to the backup file on this device
}

// rootRecover restores the root key from a backup and the recovery code. It
// refuses when a root already exists.
func (s *Server) rootRecover(w http.ResponseWriter, r *http.Request) {
	if !s.failures.open(maxRecovery) {
		w.Header().Set("Retry-After", "60")
		reply(w, http.StatusTooManyRequests, errBody("too many failed recovery attempts"))
		return
	}
	var in recoverReq
	if !decode(w, r, &in) {
		return
	}
	if exists, err := s.Store.Exists(); err != nil {
		reply(w, http.StatusInternalServerError, errBody("cannot check for a root key"))
		return
	} else if exists {
		reply(w, http.StatusConflict, errBody(root.ErrExists.Error()))
		return
	}
	backup := in.Backup
	if backup == nil {
		var err error
		if backup, err = os.ReadFile(s.BackupPath); err != nil {
			reply(w, http.StatusNotFound, errBody("no backup file found; supply the backup"))
			return
		}
	}
	k, err := root.Recover(in.RecoveryCode, backup)
	if err != nil {
		s.failures.hit()
		reply(w, http.StatusForbidden, errBody(root.ErrBadRecovery.Error()))
		return
	}
	if err := s.Store.Save(k); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, root.ErrExists) {
			code = http.StatusConflict
		}
		reply(w, code, errBody("cannot save the root key"))
		return
	}
	reply(w, http.StatusOK, statusResp{true, root.Fingerprint(k.Public().(ed25519.PublicKey))})
}

type bindingReq struct {
	Tenant     string `json:"tenant"`
	ID         string `json:"id"` // the enrollment request id, which becomes the device id
	Owner      string `json:"owner"`
	SigningKey []byte `json:"signing_key"`
	Version    uint64 `json:"version"`
}

// signBinding signs the binding for an approved request. The signer, not the
// caller, picks the expiry.
func (s *Server) signBinding(w http.ResponseWriter, r *http.Request) {
	var in bindingReq
	if !decode(w, r, &in) {
		return
	}
	k, ok := s.key(w)
	if !ok {
		return
	}
	b, err := trust.SignApproval(k, in.Tenant, trust.Pending{ID: in.ID, Owner: in.Owner, SigningKey: in.SigningKey}, in.Version, s.now())
	if err != nil {
		reply(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	reply(w, http.StatusOK, b)
}

type revocationReq struct {
	Tenant string             `json:"tenant"`
	Prev   *revocation.Signed `json:"prev"` // the current list, or null for the first
	Add    []string           `json:"add"`  // device ids to revoke; none is a refresh
}

// signRevocation signs the successor of the list the caller holds. The previous
// list must carry our own signature and be the newest we issued, so a caller
// cannot make us sign on top of a list we never issued or an outdated one.
func (s *Server) signRevocation(w http.ResponseWriter, r *http.Request) {
	var in revocationReq
	if !decode(w, r, &in) {
		return
	}
	k, ok := s.key(w)
	if !ok {
		return
	}
	if s.Revocations == nil {
		reply(w, http.StatusInternalServerError, errBody("no revocation store configured"))
		return
	}
	s.issueMu.Lock()
	defer s.issueMu.Unlock()
	if in.Prev != nil {
		if err := revocation.Verify(k.Public().(ed25519.PublicKey), in.Prev, s.now()); err != nil {
			reply(w, http.StatusBadRequest, errBody("previous list does not verify against this root"))
			return
		}
	}
	cur, err := s.Revocations.Load()
	if err != nil {
		reply(w, http.StatusInternalServerError, errBody("cannot read the issued revocation list"))
		return
	}
	if cur != nil && (in.Prev == nil || in.Prev.Version < cur.Version) {
		reply(w, http.StatusConflict, errBody("previous list is not the newest issued; fetch the current list"))
		return
	}
	l, err := revocation.Next(k, in.Tenant, in.Prev, in.Add, s.now())
	if err != nil {
		reply(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	// Durable before the caller sees it, so a restart cannot forget a list that is already out.
	if err := s.Revocations.Save(l); err != nil {
		reply(w, http.StatusInternalServerError, errBody("cannot save the issued revocation list"))
		return
	}
	reply(w, http.StatusOK, l)
}
