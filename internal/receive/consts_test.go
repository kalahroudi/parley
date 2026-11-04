// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package receive

import (
	"testing"
	"time"
)

// Pinned so a changed constant is a deliberate, reviewed edit (these expressions
// have no statement for mutation testing to cover; see tests/coverage/README.md).
func TestConstantsArePinned(t *testing.T) {
	if DefaultSkew != 2*time.Minute {
		t.Fatalf("DefaultSkew %v", DefaultSkew)
	}
	for i, s := range []Stage{StageAuthenticated, StageRecorded, StageOpened, StageErased, StageAcked} {
		if int(s) != i+1 {
			t.Fatalf("stage %d has value %d", i+1, s)
		}
	}
}
