// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package releasekey

import (
	"os"
	"testing"

	"github.com/kalahroudi/parley/internal/release"
)

// The embedded key is the committed key file, parses, and a caller cannot change the copy the binary holds.
func TestPublicIsTheCommittedKey(t *testing.T) {
	disk, err := os.ReadFile("release.pub")
	if err != nil {
		t.Fatal(err)
	}
	got := Public()
	if string(got) != string(disk) {
		t.Fatal("embedded key differs from release.pub")
	}
	if _, err := release.ParsePublicKey(got); err != nil {
		t.Fatal(err)
	}
	got[0] ^= 0xff
	if string(Public()) != string(disk) {
		t.Fatal("Public returned the shared buffer")
	}
}
