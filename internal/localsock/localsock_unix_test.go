// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package localsock

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSocketIsPrivate(t *testing.T) {
	ts := startServer(t, nil)
	fi, err := os.Stat(ts.path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode: %v %v", fi.Mode(), err)
	}
	di, _ := os.Stat(filepath.Dir(ts.path))
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode: %v", di.Mode())
	}
}

func TestSocketRefusesOtherUsers(t *testing.T) {
	m := map[string]Method{"x": func(context.Context, json.RawMessage) (any, error) { return 1, nil }}
	// A server that only admits another uid sees this process as a stranger.
	ts := startServerAs(t, os.Geteuid()+1, m)
	r, err := Call(context.Background(), ts.path, "x", nil)
	if err == nil && r.OK {
		t.Fatal("a connection from a different uid was served")
	}
	waitFor(t, "refusal logged", func() bool { return strings.Contains(ts.log.String(), "not this user") })
	if own := startServer(t, m); true {
		if r, err := Call(context.Background(), own.path, "x", nil); err != nil || !r.OK {
			t.Errorf("own uid must be served: %+v %v", r, err)
		}
	}
}
