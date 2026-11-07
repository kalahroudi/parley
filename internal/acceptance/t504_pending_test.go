// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

import "testing"

// T504 so far: internal/update verifies and installs a release signed by the pinned project key (unit and
// mutation tested). Still to build, and named here so it fails CI once T504 is ticked: the daemon's background
// update component and `parley-cli update`, the Homebrew formula, the Debian package and the apt repository,
// the JJ-01 journey test, and a check from a real signed tag on clean macOS and Linux machines. The wiring also owes
// an operator opt-out (pin or off), a refusal to run as a user other than the owner of the install directory, and a
// signed expiry in the release comment (today only the gateway's protocol-version check bounds a frozen mirror).
func TestPending_T504WiringAndChannels(t *testing.T) {
	pending(t, "T504", "wire internal/update into parleyd and parley-cli, publish the Homebrew tap and apt repository, and prove "+
		"a daemon installed from a real release updates itself to the next real tag while a pinned one does not; "+
		"add the opt-out, the owner check and the signed expiry")
}
