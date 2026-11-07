// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package fsowner

import (
	"os"
	"path/filepath"
	"testing"
)

// A directory and file this test just made belong to the user running it.
func TestInspectOwnFiles(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "f")
	os.WriteFile(f, nil, 0o600)
	if got, err := Inspect(d); err != nil || !got.IsDir || !got.Owned {
		t.Fatalf("dir: %+v %v", got, err)
	}
	if got, err := Inspect(f); err != nil || !got.IsRegular || !got.Owned {
		t.Fatalf("file: %+v %v", got, err)
	}
	if _, err := Inspect(filepath.Join(d, "missing")); err == nil {
		t.Fatal("missing path accepted")
	}
}

// The Windows directory belongs to the system's installer, not to the user running the test, whoever that is.
func TestInspectSystemDirectoryIsNotOurs(t *testing.T) {
	got, err := Inspect(os.Getenv("SystemRoot"))
	if err != nil || !got.IsDir || got.Owned {
		t.Fatalf("%+v %v", got, err)
	}
}
