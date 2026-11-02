// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package prekey

import "testing"

func TestNoPortableUndumpable(t *testing.T) {
	if markUndumpable() != nil || adviseNoDump(nil) != nil {
		t.Fatal("expected no-ops")
	}
}
