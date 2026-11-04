// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"testing"
	"time"
)

// Pinned so a changed constant is a deliberate, reviewed edit (these expressions
// have no statement for mutation testing to cover; see tests/coverage/README.md).
func TestConstantsArePinned(t *testing.T) {
	if Lifetime != 90*24*time.Hour || lockTimeout != 10*time.Second || lockPoll != 10*time.Millisecond {
		t.Fatalf("Lifetime %v, lockTimeout %v, lockPoll %v", Lifetime, lockTimeout, lockPoll)
	}
}
