// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package toolrun

import (
	"errors"
	"testing"
)

func TestNoSandboxHereSoNoToolRuns(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrNoSandbox) {
		t.Fatalf("%v", err)
	}
}
