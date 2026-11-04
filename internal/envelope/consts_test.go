// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package envelope

import "testing"

// Pinned so a changed constant is a deliberate, reviewed edit (these expressions
// have no statement for mutation testing to cover; see tests/coverage/README.md).
// The type codes are on the wire and signed, so their numbers can never move.
func TestConstantsArePinned(t *testing.T) {
	if MaxFieldSize != 65536 || MaxCiphertextSize != 16777216 || FileChunkSize != 65536 || MaxFileSize != 1073741824 || MaxPadded != 8388608 {
		t.Fatalf("sizes: %d %d %d %d %d", MaxFieldSize, MaxCiphertextSize, FileChunkSize, MaxFileSize, MaxPadded)
	}
	for i, ty := range []Type{TypeTask, TypeStatus, TypeInputRequired, TypeResult, TypeError, TypeCancel, TypeReply} {
		if int(ty) != i+1 {
			t.Fatalf("type %d has code %d", i+1, ty)
		}
	}
}
