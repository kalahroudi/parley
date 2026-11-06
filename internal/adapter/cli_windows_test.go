// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package adapter

import (
	"os/exec"
	"testing"
)

// A command that has already been reaped cannot be put in a job: containment fails rather than being skipped.
func TestContainTreeFailsForAProcessThatIsGone(t *testing.T) {
	cmd := exec.Command("cmd", "/c", "exit", "0")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if kill, err := containTree(cmd); err == nil || kill != nil {
		t.Fatalf("contained a reaped process: %v", err)
	}
}
