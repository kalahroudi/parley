// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/fsperm"
)

func TestErrorCodes(t *testing.T) {
	for want, err := range map[string]error{
		"signature": ErrSignature, "expired": ErrExpired, "not_yet": ErrNotYetValid, "not_owner": ErrNotOwner,
		"not_release": ErrNotRelease, "managed": ErrManaged, "pin": ErrVersion, "busy": fsperm.ErrLocked,
		"failed": errors.New("connection refused"),
	} {
		if got := ErrorCode(err); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
		if got := ErrorCode(fmt.Errorf("wrapped: %w", err)); got != want {
			t.Errorf("wrapped %v: %q, want %q", err, got, want)
		}
	}
	// A message never decides the code: only the error's identity does.
	if ErrorCode(errors.New("update: release signature rejected")) != "failed" {
		t.Fatal("matched on text")
	}
}

func TestStatusRoundTrip(t *testing.T) {
	d := t.TempDir()
	if _, ok, err := ReadStatus(d); ok || err != nil {
		t.Fatalf("empty: %v %v", ok, err)
	}
	want := Status{State: StateError, CheckedAt: 1800000000, Current: "v1.0.0", Code: "expired"}
	for i := 0; i < 2; i++ { // the second write replaces the first
		if err := WriteStatus(d, want); err != nil {
			t.Fatal(err)
		}
	}
	got, ok, err := ReadStatus(d)
	if err != nil || !ok || got != want || !got.CheckedTime().Equal(time.Unix(1800000000, 0)) {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
	if ents, _ := os.ReadDir(d); len(ents) != 1 {
		t.Fatalf("temporary files left: %v", ents)
	}
	if fi, _ := os.Stat(filepath.Join(d, StatusFile)); runtimeIsUnix() && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	for _, s := range []Status{
		{State: StateUpToDate, Current: "v1.0.0"}, {State: StateAvailable, Current: "v1.0.0", Available: "v1.1.0"},
		{State: StateInstalled, Current: "v1.0.0", Available: "v1.1.0"}, {State: StateError, Current: "v1.0.0", Code: "failed"},
	} {
		WriteStatus(d, s)
		if got, ok, err := ReadStatus(d); err != nil || !ok || got != s {
			t.Fatalf("%+v: %+v %v %v", s, got, ok, err)
		}
	}
}

func TestWriteStatusErrors(t *testing.T) {
	if err := WriteStatus(filepath.Join(t.TempDir(), "missing"), Status{}); err == nil {
		t.Fatal("missing directory accepted")
	}
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, StatusFile, "x"), 0o700) // a non-empty directory cannot be replaced by a file
	if err := WriteStatus(d, Status{State: StateUpToDate, Current: "v1.0.0"}); err == nil {
		t.Fatal("rename onto a directory accepted")
	}
	if ents, _ := os.ReadDir(d); len(ents) != 1 {
		t.Fatalf("temporary file left behind: %v", ents)
	}
}

// The record is only ever written by this package, so anything else in it is refused rather than printed.
func TestReadStatusRefusesAnythingUnexpected(t *testing.T) {
	good := `{"state":"error","checked_at":1,"current":"v1.0.0","code":"expired"}`
	for name, body := range map[string]string{
		"unknown field": `{"state":"up_to_date","checked_at":1,"current":"v1.0.0","note":"hi"}`,
		"trailing data": good + good,
		"not json":      "x",
		"bad state":     `{"state":"great","checked_at":1,"current":"v1.0.0"}`,
		"bad current":   `{"state":"up_to_date","checked_at":1,"current":"dev"}`,
		"bad available": `{"state":"available","checked_at":1,"current":"v1.0.0","available":"latest"}`,
		"bad code":      `{"state":"error","checked_at":1,"current":"v1.0.0","code":"disk on fire"}`,
		"too large":     `{"state":"error","checked_at":1,"current":"v1.0.0","code":"` + strings.Repeat("x", maxStatusBytes) + `"}`,
		"empty":         "",
		"control text":  `{"state":"error","checked_at":1,"current":"v1.0.0","code":"\u001b[31m"}`,
	} {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, StatusFile), []byte(body), 0o600)
		if _, ok, err := ReadStatus(d); ok || err == nil {
			t.Errorf("%s: accepted (%v, %v)", name, ok, err)
		}
	}
	d := t.TempDir()
	os.Mkdir(filepath.Join(d, StatusFile), 0o700) // a directory where the file should be
	if _, ok, err := ReadStatus(d); ok || err == nil {
		t.Errorf("directory accepted (%v, %v)", ok, err)
	}
}

func runtimeIsUnix() bool { return os.PathSeparator == '/' }

// A path the operating system rejects outright is an error, not "no record".
func TestReadStatusUnopenablePath(t *testing.T) {
	if _, ok, err := ReadStatus(t.TempDir() + "\x00"); ok || err == nil {
		t.Fatalf("(%v, %v)", ok, err)
	}
}

// The size limit is exact: a record of exactly the limit is read, one byte more is refused.
func TestReadStatusSizeLimitIsExact(t *testing.T) {
	rec := `{"state":"up_to_date","checked_at":1,"current":"v1.0.0"}`
	for pad, ok := range map[int]bool{maxStatusBytes - len(rec): true, maxStatusBytes - len(rec) + 1: false} {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, StatusFile), []byte(rec+strings.Repeat(" ", pad)), 0o600)
		if _, got, err := ReadStatus(d); got != ok || (err == nil) != ok {
			t.Errorf("%d bytes: ok=%v err=%v, want ok=%v", len(rec)+pad, got, err, ok)
		}
	}
}
