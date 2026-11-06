// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ptytest

import (
	"errors"
	"os/exec"
	"testing"
)

func TestStartIsUnsupportedOnWindows(t *testing.T) {
	if _, err := Start(exec.Command("cmd")); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("%v", err)
	}
}
