// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

import "testing"

// T504 so far: internal/update has the building blocks (verify a release signed by the pinned project key, replace
// the binaries) and they are not wired anywhere or enabled. Still owed by T504, named here so this fails CI once
// T504 is ticked:
//   - the daemon's background update component and `parley-cli update`;
//   - an operator opt-out (pin or off);
//   - the Homebrew formula and tap, the Debian package and the apt repository;
//   - the JJ-01 journey test, and a check from a real signed tag on clean macOS and Linux machines (T511 covers
//     fresh-machine installs).
func TestPending_T504WiringAndChannels(t *testing.T) {
	pending(t, "T504", "wire internal/update into parleyd and parley-cli with an opt-out; "+
		"publish the Homebrew tap and the apt repository; prove on clean machines (T511) that a daemon installed from a real "+
		"release updates itself to the next real tag while a pinned one does not")
}
