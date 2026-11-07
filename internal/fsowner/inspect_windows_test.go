// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package fsowner

import (
	"os"
	"os/exec"
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

// An allow entry for Everyone that writes is seen; one that only reads is not; full control also takes over.
func TestInspectOthersWrite(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "f")
	os.WriteFile(f, nil, 0o600)
	if got, err := Inspect(f); err != nil || got.GroupOrOtherWrite || got.WorldWrite {
		t.Fatalf("private file: %+v %v", got, err)
	}
	grant := func(path, rights string) {
		t.Helper()
		if out, err := exec.Command("icacls", path, "/grant", "*S-1-1-0:"+rights).CombinedOutput(); err != nil { // Everyone
			t.Fatalf("icacls: %v: %s", err, out)
		}
	}
	grant(f, "R")
	if got, _ := Inspect(f); got.GroupOrOtherWrite || got.WorldWrite {
		t.Fatalf("read-only grant: %+v", got)
	}
	grant(f, "W")
	if got, _ := Inspect(f); !got.GroupOrOtherWrite || got.WorldWrite {
		t.Fatalf("write grant: %+v", got)
	}
	grant(f, "F")
	// Objects owned by the system (an elevated runner owns what it creates as Administrators) keep WorldWrite false.
	if got, _ := Inspect(f); !got.GroupOrOtherWrite || got.WorldWrite == got.Trusted {
		t.Fatalf("full-control grant: %+v", got)
	}
	grant(d, "(OI)(CI)(DC)")
	if got, _ := Inspect(d); !got.GroupOrOtherWrite || got.WorldWrite == got.Trusted {
		t.Fatalf("delete-child grant on directory: %+v", got)
	}
}
