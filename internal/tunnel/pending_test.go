// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pending marks a test that cannot be written until task is built. It skips with the reason while the task is
// open and FAILS once tasks.md ticks the task (same contract as internal/acceptance and tests/harness/pending.mjs).
func pending(t *testing.T, task, reason string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "specs", "parley-mvp", "tasks.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "- [x] "+task+" ") {
			t.Fatalf("%s is ticked but this acceptance test is still pending: write it (%s)", task, reason)
		}
	}
	t.Skipf("pending %s: %s", task, reason)
}

// Parked until T310: /v1/connect is closed until device connect tokens exist, so the daemon's tunnel client cannot
// be run against a real gateway. TestAgainstWorker below holds the assertions (hello, welcome, ack, reconnect) and
// runs when PARLEY_TEST_GATEWAY and PARLEY_TEST_GATEWAY_TOKEN are given.
func TestPending_TunnelAgainstRealGateway(t *testing.T) {
	pending(t, "T310", "run TestAgainstWorker in CI against `wrangler dev` with a connect token issued by the enrollment flow")
}
