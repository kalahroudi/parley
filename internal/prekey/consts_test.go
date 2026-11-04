// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package prekey

import (
	"testing"
	"time"
)

// Pinned so a changed constant is a deliberate, reviewed edit (these expressions
// have no statement for mutation testing to cover; see tests/coverage/README.md).
func TestConstantsArePinned(t *testing.T) {
	if DefaultTTL != 15*time.Minute || MaxTTL != 24*time.Hour || DefaultSkew != 2*time.Minute || DefaultSweep != 5*time.Second {
		t.Fatalf("%v %v %v %v", DefaultTTL, MaxTTL, DefaultSkew, DefaultSweep)
	}
	if MaxCapacity != 65536 || DefaultTombstones != 65536 {
		t.Fatalf("%d %d", MaxCapacity, DefaultTombstones)
	}
}
