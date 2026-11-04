// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"os"
	"testing"
)

// Runs the client against a real gateway Worker, to catch drift between this
// package and gateway/src/protocol.ts. Start one with
// `cd gateway && npx wrangler dev`, then
// PARLEY_TEST_GATEWAY=ws://127.0.0.1:8787/v1/connect PARLEY_TEST_GATEWAY_TOKEN=<token> go test ./internal/tunnel.
// The gateway has no development bypass, and device connect tokens are not
// issued yet (the Worker refuses every /v1/connect), so this stays opt-in
// until they land.
func TestAgainstWorker(t *testing.T) {
	url := os.Getenv("PARLEY_TEST_GATEWAY")
	if url == "" {
		t.Skip("PARLEY_TEST_GATEWAY not set")
	}
	token := os.Getenv("PARLEY_TEST_GATEWAY_TOKEN")
	if token == "" {
		t.Skip("PARLEY_TEST_GATEWAY_TOKEN not set")
	}
	c := New(Config{URL: url, Token: token})
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
