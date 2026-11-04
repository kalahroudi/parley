// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Device connect tokens (T415) are short-lived and checked when a connection opens, so the tunnel gets one per
// connection attempt (Config.TokenSource). These were the tests parked here until the gateway issued tokens; they now
// run against the in-process gateway (the real Worker is driven by tests/pending-t310.test.mjs through TestAgainstWorker).

func TestTokenSourceGivesEachConnectionAFreshToken(t *testing.T) {
	g := newFakeGateway(t)
	var calls atomic.Int32
	c, _, _ := start(t, g, func(cfg *Config) {
		cfg.Token = ""
		cfg.TokenSource = func(context.Context) (string, error) {
			calls.Add(1)
			return "tok", nil
		}
	})
	waitFor(t, "welcome", func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.session != "" })
	g.drop()
	waitFor(t, "a second token for the reconnect", func() bool { return calls.Load() >= 2 })
}

func TestTokenSourceErrorIsRetriedAndNeverShown(t *testing.T) {
	g := newFakeGateway(t)
	var calls atomic.Int32
	c, _, done := start(t, g, func(cfg *Config) {
		cfg.TokenSource = func(context.Context) (string, error) {
			if calls.Add(1) < 3 {
				return "", errors.New("network down pdt_secret-in-error")
			}
			return "tok", nil
		}
	})
	waitFor(t, "welcome after the source recovered", func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.session != "" })
	select {
	case err := <-done:
		t.Fatalf("Run stopped: %v", err)
	default:
	}
	// The error a source returns is not passed on, so a credential inside it cannot reach a log.
	if _, err := New(Config{TokenSource: func(context.Context) (string, error) { return "", errors.New("secret") }}).connect(context.Background()); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("connect error = %v", err)
	}
}

func TestTokenSourceRefusalStopsRun(t *testing.T) {
	g := newFakeGateway(t)
	_, _, done := start(t, g, func(cfg *Config) {
		cfg.TokenSource = func(context.Context) (string, error) { return "", fmt.Errorf("revoked: %w", ErrRefused) }
	})
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "credentials") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept retrying a refused device")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.dials != 0 {
		t.Fatal("the gateway was dialed without a token")
	}
}
