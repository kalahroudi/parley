// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// configHome writes a valid config (file key store) under a short temp dir and
// returns a userConfigDir func for it.
func configHome(t *testing.T) func() (string, error) {
	t.Helper()
	home := shortTempDir(t)
	dir := filepath.Join(home, "parley")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cfg := `{"format":1,"tenant":"t1","device_id":"dev-1","gateway_url":"http://127.0.0.1:1","key_store":"file","root_public_key":"` +
		base64.StdEncoding.EncodeToString(pub) + `"}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return func() (string, error) { return home, nil }
}

func TestRunBlocksUntilCanceledThenStopsCleanly(t *testing.T) {
	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	cfgDir := configHome(t)
	go func() { done <- runIn(ctx, noEnv, cfgDir, &logs) }()
	select {
	case err := <-done:
		t.Fatalf("returned before cancel: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("did not return after cancel")
	}
}

func TestRunInFailsClosed(t *testing.T) {
	var logs bytes.Buffer
	if err := runIn(context.Background(), noEnv, func() (string, error) { return "", errors.New("no home") }, &logs); err == nil {
		t.Error("no config dir: want error")
	}
	empty := t.TempDir()
	if err := runIn(context.Background(), noEnv, func() (string, error) { return empty, nil }, &logs); err == nil {
		t.Error("no config file: want error")
	}
	// A valid config in a world-readable directory is refused.
	if runtime.GOOS != "windows" {
		cfgDir := configHome(t)
		home, _ := cfgDir()
		os.Chmod(filepath.Join(home, "parley"), 0o755)
		if err := runIn(context.Background(), noEnv, cfgDir, &logs); err == nil {
			t.Error("open config directory: want error")
		}
	}
}

func noEnv(string) string { return "" }

func TestRunUsesTheUserConfigDir(t *testing.T) {
	// run() reads the real user config dir; with HOME pointed at an empty
	// directory there is no config, so it must refuse to start.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("AppData", t.TempDir())
	t.Setenv("PARLEY_HOME", "")
	if err := run(context.Background()); err == nil {
		t.Error("run without a config file must fail")
	}
}

func TestExecute(t *testing.T) {
	var out, errw bytes.Buffer
	ctx := context.Background()
	ok := func(context.Context) error { return nil }
	if code := execute(ctx, []string{"--version"}, &out, &errw, func(context.Context) error { t.Fatal("ran the daemon for --version"); return nil }); code != 0 || out.String() != "parleyd "+version+"\n" {
		t.Fatalf("--version: %d %q", code, out.String())
	}
	if code := execute(ctx, nil, &out, &errw, ok); code != 0 {
		t.Fatalf("clean run: %d", code)
	}
	errw.Reset()
	if code := execute(ctx, nil, &out, &errw, func(context.Context) error { return errors.New("boom") }); code != 1 || errw.String() != "parleyd: boom\n" {
		t.Fatalf("failing run: %d %q", code, errw.String())
	}
}

func TestRunHonoursParleyHome(t *testing.T) {
	cfgDir := configHome(t)
	home, _ := cfgDir()
	t.Setenv("PARLEY_HOME", filepath.Join(home, "parley"))
	t.Setenv("HOME", t.TempDir()) // the user config dir is empty: only PARLEY_HOME can supply the config
	t.Setenv("XDG_CONFIG_HOME", "")
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if err := run(ctx); err != nil {
		t.Fatalf("run with PARLEY_HOME: %v", err)
	}
}

// shortTempDir returns a short private temp directory: the socket path under it
// must fit the unix limit, and a runner's TMPDIR can be much longer.
func shortTempDir(t *testing.T) string {
	t.Helper()
	// Unix socket paths are limited to about 104 bytes (the daemon allows 100) and
	// a runner's TMPDIR can be much longer, so use /tmp where there is one.
	base := ""
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat("/tmp"); err == nil && fi.IsDir() {
			base = "/tmp"
		}
	}
	d, err := os.MkdirTemp(base, "pd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if len(d) > 70 {
		t.Fatalf("temp directory %q is too long for a socket path under it (%d characters, at most 70); set TMPDIR to a short directory", d, len(d))
	}
	return d
}
