// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// Runs the client against a real gateway Worker, to catch drift between this
// package and gateway/src/protocol.ts. Start one with
// `cd gateway && npx wrangler dev --var DEV_AUTH:1`, then
// PARLEY_TEST_GATEWAY=ws://127.0.0.1:8787/v1/connect go test ./internal/tunnel.
func TestAgainstWorker(t *testing.T) {
	url := os.Getenv("PARLEY_TEST_GATEWAY")
	if url == "" {
		t.Skip("PARLEY_TEST_GATEWAY not set")
	}
	c := New(Config{URL: url, Token: "dev:tenant-" + time.Now().Format("150405") + "-" + strconv.Itoa(os.Getpid()) + ":dev1"})
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
