// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

import "testing"

// T504 so far: internal/update verifies and installs a release signed by the pinned project key (signed expiry,
// owner check, restart-safe swap), and parleyd and parley-cli use it with an operator opt-out and pin. Still owed by
// T504, named here so this fails CI once T504 is ticked:
//   - the Homebrew formula and tap, the Debian package and the apt repository, as scripted and tested steps;
//   - the JJ-01 journey test (T509), and a check from a real signed tag on clean macOS and Linux machines (T511 covers
//     fresh-machine installs).
func TestPending_T504WiringAndChannels(t *testing.T) {
	pending(t, "T504", "publish the Homebrew tap and the apt repository; prove on clean machines (T511) and in the JJ-01 journey (T509) "+
		"that a daemon installed from a real release updates itself to the next real tag while a pinned one does not")
}
