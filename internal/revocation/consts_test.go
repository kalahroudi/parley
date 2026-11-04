// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package revocation

import (
	"testing"
	"time"
)

// Pinned so a changed constant is a deliberate, reviewed edit (these expressions
// have no statement for mutation testing to cover; see tests/coverage/README.md).
func TestConstantsArePinned(t *testing.T) {
	if WarnAfter != 168*time.Hour || RefuseAfter != 336*time.Hour || RefreshEvery != 24*time.Hour || MaxSkew != 5*time.Minute {
		t.Fatalf("%v %v %v %v", WarnAfter, RefuseAfter, RefreshEvery, MaxSkew)
	}
}
