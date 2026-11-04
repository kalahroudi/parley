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

func TestPending_DaemonRefusesToSendWithoutFreshTrustState(t *testing.T) {
	pending(t, "T412", "the daemon has no send path yet. When T412 adds one, prove it refuses to send (and sends nothing, not even a partial frame) whenever: the binding store is missing, unreadable or corrupt; the revocation list is missing, older than its refusal age, unreadable or corrupt; the revocation list revokes the recipient or this device; and that it sends again once a fresh valid list is stored. Reuse trust.Daemon, binding.Tracker and revocation.Guard; a test that passes with a re-implemented check proves nothing")
}

func TestPending_WindowsDaemonPeerRestriction(t *testing.T) {
	pending(t, "T505", "on Windows the control socket is AF_UNIX in a protected-DACL directory with no peer-credential check (see internal/localsock). Assert the Windows daemon uses a named pipe with a current-user-only ACL, or an equivalent peer check, and that a process of another local user cannot connect, while the same user can; also that the DACL check refuses a pipe or directory open to Everyone, Users or Authenticated Users")
}
