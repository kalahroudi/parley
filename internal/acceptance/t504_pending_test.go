// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

import "testing"

// T504 so far: internal/update verifies and installs a release signed by the pinned project key (signed expiry,
// owner check, restart-safe swap), parleyd and parley-cli use it with an operator opt-out and pin, and the release
// builds the Homebrew formula and the Debian packages and has verified, tested scripts that publish them to the tap
// and to an apt repository signed with the project key. Still owed, named here so this fails CI once T504 is ticked:
//   - running those scripts from the release workflow with the project's secrets, and the first real publication
//     (the tap repository and the Pages branch are created by the project owner);
//   - the JJ-01 journey test (T509), and a check from a real signed tag on clean macOS and Linux machines (T511 covers
//     fresh-machine installs).
func TestPending_T504WiringAndChannels(t *testing.T) {
	pending(t, "T504", "run publish-tap.sh and publish-apt.sh from the release workflow with the project's secrets and publish a real tag; "+
		"prove on clean machines (T511) and in the JJ-01 journey (T509) that a daemon installed from a real release updates itself "+
		"to the next real tag while a pinned one does not")
}
