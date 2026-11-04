// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

import "testing"

// T410 builds the daemon core. What it deliberately leaves to later tasks is
// named here, so it cannot be forgotten: each test skips while its task is open
// and fails once tasks.md ticks the task.

func TestPending_DaemonGetsConnectTokenAndConnects(t *testing.T) {
	pending(t, "T415", "parleyd's default TunnelConfig returns ErrNoConnectToken; assert a daemon with a device connect token connects to a real gateway and holds the tunnel open")
}

func TestPending_DaemonProcessesTunnelEvents(t *testing.T) {
	pending(t, "T412", "parleyd's OnEvent is a no-op; assert tasks pushed through the tunnel reach the receive pipeline (open, verify, erase, ack, execute) and nothing is dropped")
}

func TestPending_DaemonEnrollmentAndBindings(t *testing.T) {
	pending(t, "T411", "the daemon core opens the binding tracker but has no enrollment flow; assert a fresh daemon enrolls, receives its root-signed binding and records it before serving")
}
