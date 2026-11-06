// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/envelope"
)

// self is an absolute path that exists on every OS; the bot is never started in these tests.
func self(t *testing.T) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "botd")
	if err != nil {
		dir = t.TempDir()
	} else {
		t.Cleanup(func() { os.RemoveAll(dir) })
	}
	return dir
}

func writeConfig(t *testing.T, dir, gateway string) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := json.Marshal(daemon.Config{Format: 1, Tenant: "t1", DeviceID: "dev-1", GatewayURL: gateway, RootPublicKey: pub, KeyStore: daemon.KeyStoreFile})
	if err := os.WriteFile(dir+"/config.json", raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunRefusesBadStartups(t *testing.T) {
	dir := shortDir(t)
	env := func(k string) string {
		if k == "PARLEY_HOME" {
			return dir
		}
		return ""
	}
	ctx := context.Background()
	if err := run(ctx, []string{"-nope"}, env, io.Discard); err == nil {
		t.Fatal("an unknown flag was accepted")
	}
	if err := run(ctx, nil, env, io.Discard); err == nil {
		t.Fatal("started without a configuration")
	}
	writeConfig(t, dir, "http://127.0.0.1:1")
	if err := run(ctx, []string{"-command", "relative/bot"}, env, io.Discard); err == nil {
		t.Fatal("a relative bot command was accepted")
	}
}

func TestRunServesUntilCanceled(t *testing.T) {
	dir := shortDir(t)
	writeConfig(t, dir, "http://127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	log := &syncLog{started: cancel}
	err := run(ctx, []string{"-owner", "svc-ci", "-command", self(t)}, func(k string) string {
		if k == "PARLEY_HOME" {
			return dir
		}
		return ""
	}, log)
	if err != nil {
		t.Fatalf("%v: %s", err, log.String())
	}
	if !strings.Contains(log.String(), "parleyd started") {
		t.Fatalf("the daemon did not start: %q", log.String())
	}
}

func TestAllowOwnerMatchesOnlyThatOwner(t *testing.T) {
	allow := allowOwner("svc-ci")
	if !allow("SVC-CI") || allow("svc-other") || allow("") {
		t.Fatal("the allowlist is not exactly the one owner")
	}
}

func TestServeReportsFailureAndStopsWhenTold(t *testing.T) {
	dir := shortDir(t)
	env := func(k string) string {
		if k == "PARLEY_HOME" {
			return dir
		}
		return ""
	}
	var out strings.Builder
	if code := serve(context.Background(), nil, env, &out); code != 1 || !strings.Contains(out.String(), "botd:") {
		t.Fatalf("code %d, output %q", code, out.String())
	}
	writeConfig(t, dir, "http://127.0.0.1:1")
	// Stopped once it says it started, not after a fixed time: a slow runner may need seconds to start.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	log := &syncLog{started: cancel}
	if code := serve(ctx, []string{"-command", self(t)}, env, log); code != 0 {
		t.Fatalf("a daemon told to stop exited with %d: %s", code, log.String())
	}
	if !strings.Contains(log.String(), "parleyd started") {
		t.Fatalf("the daemon did not start: %q", log.String())
	}
}

// syncLog is a log the daemon writes from several goroutines; it calls started the first time the daemon says so.
type syncLog struct {
	mu      sync.Mutex
	b       strings.Builder
	started func()
}

func (l *syncLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.b.Write(p)
	if strings.Contains(l.b.String(), "parleyd started") {
		l.started()
	}
	return n, err
}

func (l *syncLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestResponderFailsBeforeEnrollment(t *testing.T) {
	dir := shortDir(t)
	writeConfig(t, dir, "http://127.0.0.1:1")
	cfg, err := daemon.LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := daemon.New(cfg, daemon.Dirs{Config: dir, State: dir}, daemon.Deps{Log: daemon.NewLogger(io.Discard, ""), Harden: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&responder{d}).Respond(context.Background(), [16]byte{}, envelope.TypeResult, []byte("x")); err == nil {
		t.Fatal("an unenrolled daemon answered")
	}
}

func TestPublishRetriesUntilTheGatewayAccepts(t *testing.T) {
	var published atomic.Int32
	var card struct {
		Card struct{ Name string }
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/connect/challenge":
			json.NewEncoder(w).Encode(map[string]any{"challenge": "c", "expires_at": 4102444800000})
		case "/v1/connect/token":
			json.NewEncoder(w).Encode(map[string]any{"token": "tok", "expires_at": 4102444800000})
		case "/v1/cards/publish":
			if r.Header.Get("Authorization") != "Bearer tok" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			if published.Add(1) == 1 {
				http.Error(w, "try again", http.StatusServiceUnavailable)
				return
			}
			json.NewDecoder(r.Body).Decode(&card)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	cfg := daemon.Config{Tenant: "t1", DeviceID: "dev-1", GatewayURL: srv.URL}
	var calls atomic.Int32
	version := func() (uint64, bool) { return 3, calls.Add(1) > 1 } // not enrolled on the first look
	done := make(chan struct{})
	go func() { publish(context.Background(), cfg, key, version, "the-bot"); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("publish did not finish")
	}
	if published.Load() != 2 || card.Card.Name != "the-bot" {
		t.Fatalf("publishes %d, card %+v", published.Load(), card)
	}
}

func TestPublishStopsWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		publish(ctx, daemon.Config{GatewayURL: "http://127.0.0.1:1"}, nil, func() (uint64, bool) { return 0, false }, "x")
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publish ignored cancellation")
	}
}
