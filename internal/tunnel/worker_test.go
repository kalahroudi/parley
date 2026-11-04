// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"strconv"
	"testing"

	"github.com/kalahroudi/parley/internal/connect"
)

// Runs the client against a real gateway Worker, to catch drift between this
// package and gateway/src/protocol.ts. Start one with
// `cd gateway && npx wrangler dev`, then
// PARLEY_TEST_GATEWAY=ws://127.0.0.1:8787/v1/connect PARLEY_TEST_GATEWAY_TOKEN=<token> go test ./internal/tunnel.
// A device connect token is single use, so with PARLEY_TEST_GATEWAY_BASE (the http URL), _TENANT, _DEVICE,
// _SEED (the device's hex Ed25519 seed) and _VERSION (its binding version) the client earns its own tokens
// with internal/connect, one per connection attempt, the way the daemon does. That is how
// tests/pending-t310.test.mjs runs it in CI, against a gateway it started and a device it enrolled.
func TestAgainstWorker(t *testing.T) {
	url := os.Getenv("PARLEY_TEST_GATEWAY")
	if url == "" {
		t.Skip("PARLEY_TEST_GATEWAY not set")
	}
	cfg := Config{URL: url, Token: os.Getenv("PARLEY_TEST_GATEWAY_TOKEN")}
	if seed := os.Getenv("PARLEY_TEST_GATEWAY_SEED"); seed != "" {
		raw, err := hex.DecodeString(seed)
		version, verr := strconv.ParseUint(os.Getenv("PARLEY_TEST_GATEWAY_VERSION"), 10, 64)
		if err != nil || len(raw) != ed25519.SeedSize || verr != nil {
			t.Fatal("PARLEY_TEST_GATEWAY_SEED or _VERSION is not valid")
		}
		key := ed25519.NewKeyFromSeed(raw)
		cl := &connect.Client{BaseURL: os.Getenv("PARLEY_TEST_GATEWAY_BASE"), Tenant: os.Getenv("PARLEY_TEST_GATEWAY_TENANT"), Device: os.Getenv("PARLEY_TEST_GATEWAY_DEVICE")}
		cfg.TokenSource = func(ctx context.Context) (string, error) {
			tok, err := cl.Token(ctx, key, version, connect.ScopeConnect)
			return tok.Secret, err
		}
	} else if cfg.Token == "" {
		t.Skip("PARLEY_TEST_GATEWAY_TOKEN not set")
	}
	c := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	for i := 0; i < 5; i++ {
		if err := c.Send("hello"); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "frames acked by the worker", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.session != "" && len(c.outbox) == 0
	})
	cancel()
	<-done
}
