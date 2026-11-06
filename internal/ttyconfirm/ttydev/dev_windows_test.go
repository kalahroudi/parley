// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ttydev

import "testing"

// Open succeeds only on a console and fails otherwise, and never panics.
func TestOpenConsole(t *testing.T) {
	if _, closeFn, err := Open(); err == nil {
		closeFn()
	}
}
