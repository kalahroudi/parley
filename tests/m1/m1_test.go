// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package m1 runs milestone M1 (T414): real parleyd processes and the real parley-cli, through the real gateway
// (`wrangler dev`), driven by tests/m1-echo.test.mjs. It fails, rather than skips, when node or the gateway's
// dependencies are missing: a passing run means the echo happened.
package m1

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestEncryptedEchoBetweenTwoDaemonsThroughTheGateway(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal("node is required for the M1 test")
	}
	if _, err := os.Stat(filepath.Join(root, "gateway", "node_modules", ".bin")); err != nil {
		t.Fatal("gateway dependencies missing: cd gateway && npm ci")
	}
	cmd := exec.Command("node", "--test", filepath.Join("tests", "m1-echo.test.mjs"))
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the M1 echo failed: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}
