// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package bottest_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The fake bot and the contract suite are test support: no program we ship may
// link them (the contract suite pulls in "testing").
func TestNoShippedProgramLinksBottest(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "../../../cmd/...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, p := range strings.Fields(string(out)) {
		// The ACP SDK is the conformance tests' reference peer (a test-only dependency), the adaptertest package their agents.
		if strings.HasSuffix(p, "/internal/bot/bottest") || strings.HasSuffix(p, "/internal/adapter/adaptertest") ||
			strings.HasPrefix(p, "github.com/coder/acp-go-sdk") || p == "testing" {
			t.Fatalf("a shipped program depends on %s", p)
		}
	}
}
