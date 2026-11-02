// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecute(t *testing.T) {
	cfg := t.TempDir()
	dir := func() (string, error) { return cfg, nil }
	var out, errw bytes.Buffer

	if code := execute([]string{"--version"}, &out, &errw, dir); code != 0 || out.String() != "parley-cli "+version+"\n" {
		t.Fatalf("--version: %d %q", code, out.String())
	}

	out.Reset()
	if code := execute([]string{"admin", "init"}, &out, &errw, dir); code != 0 || !strings.Contains(out.String(), "Recovery code: ") {
		t.Fatalf("admin init: %d out=%q err=%q", code, out.String(), errw.String())
	}
	// The key and backup went under <config>/parley.
	for _, f := range []string{"root.key", "root-backup.json"} {
		if _, err := os.Stat(filepath.Join(cfg, "parley", f)); err != nil {
			t.Errorf("%s not written: %v", f, err)
		}
	}

	errw.Reset()
	if code := execute([]string{"admin", "init"}, &out, &errw, func() (string, error) { return "", errors.New("no home") }); code != 1 || errw.String() != "error: no home\n" {
		t.Fatalf("no config dir: %d %q", code, errw.String())
	}

	for _, args := range [][]string{nil, {"admin"}, {"bogus"}, {"--version", "x"}} {
		errw.Reset()
		if code := execute(args, &out, &errw, dir); code != 2 || !strings.Contains(errw.String(), "usage:") {
			t.Errorf("%v: %d %q", args, code, errw.String())
		}
	}
}
