// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"testing"
	"time"
)

// Pinned so a changed constant is a deliberate, reviewed edit (these expressions
// have no statement for mutation testing to cover; see tests/coverage/README.md).
func TestConstantsArePinned(t *testing.T) {
	if DefaultMaxEntries != 1048576 || DefaultMaxPerSender != 65536 || DefaultMaxLifetime != 24*time.Hour || DefaultSkew != 5*time.Minute {
		t.Fatalf("%d %d %v %v", DefaultMaxEntries, DefaultMaxPerSender, DefaultMaxLifetime, DefaultSkew)
	}
}
