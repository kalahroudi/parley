// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExecute(t *testing.T) {
	cfg := t.TempDir()
	dir := func() (string, error) { return cfg, nil }
	var out, errw bytes.Buffer

	if code := runExec([]string{"--version"}, &out, &errw, dir); code != 0 || out.String() != "parley-cli "+version+"\n" {
		t.Fatalf("--version: %d %q", code, out.String())
	}

	out.Reset()
	if code := runExec([]string{"admin", "init"}, &out, &errw, dir); code != 0 || !strings.Contains(out.String(), "Recovery code: ") {
		t.Fatalf("admin init: %d out=%q err=%q", code, out.String(), errw.String())
	}
	// The key and backup went under <config>/parley.
	for _, f := range []string{"root.key", "root-backup.json"} {
		if _, err := os.Stat(filepath.Join(cfg, "parley", f)); err != nil {
			t.Errorf("%s not written: %v", f, err)
		}
	}

	errw.Reset()
	if code := runExec([]string{"admin", "init"}, &out, &errw, func() (string, error) { return "", errors.New("no home") }); code != 1 || errw.String() != "error: no home\n" {
		t.Fatalf("no config dir: %d %q", code, errw.String())
	}

	for _, args := range [][]string{nil, {"admin"}, {"bogus"}, {"--version", "x"}} {
		errw.Reset()
		if code := runExec(args, &out, &errw, dir); code != 2 || !strings.Contains(errw.String(), "usage:") {
			t.Errorf("%v: %d %q", args, code, errw.String())
		}
	}
}

// run is execute with no environment and no enrollment (the commands that need them have their own tests).
func runExec(args []string, out, errw io.Writer, dir func() (string, error)) int {
	return execute(context.Background(), args, strings.NewReader(""), out, errw, dir, func(string) string { return "" }, tools{})
}

func runCtx(ctx context.Context, args []string, out, errw io.Writer, dir func() (string, error)) int {
	return execute(ctx, args, strings.NewReader(""), out, errw, dir, func(string) string { return "" }, tools{})
}

func TestSignerCommand(t *testing.T) {
	cfg := t.TempDir()
	dir := func() (string, error) { return cfg, nil }
	ctx, cancel := context.WithCancel(context.Background())
	info := filepath.Join(cfg, "parley", "signer.json")
	// A stale, world-readable file from a dead signer must not survive as 0644.
	os.MkdirAll(filepath.Dir(info), 0o755)
	os.WriteFile(info, []byte("{}"), 0o644)
	var out, errw syncBuffer
	done := make(chan int)
	go func() { done <- runCtx(ctx, []string{"signer"}, &out, &errw, dir) }()

	var si signerInfo
	for i := 0; i < 1200; i++ {
		if b, err := os.ReadFile(info); err == nil && json.Unmarshal(b, &si) == nil && si.Addr != "" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if si.Addr == "" || si.Secret == "" {
		t.Fatalf("no info file: %q", errw.String())
	}
	// Unix: the secret file is owner-only. Windows ignores mode bits; there the
	// file keeps the ACL it inherits from the per-user config directory.
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(info); fi.Mode().Perm() != 0o600 {
			t.Errorf("info file mode %v", fi.Mode().Perm())
		}
	}
	if strings.Contains(out.String(), si.Secret) {
		t.Error("secret printed")
	}
	req, _ := http.NewRequest("GET", "http://"+si.Addr+"/v1/root", nil)
	req.Header.Set("Authorization", "Bearer "+si.Secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("status: %v %v", resp, err)
	}
	resp.Body.Close()

	// Drive init through the live signer, then check that neither stream the
	// process writes carries the key, the recovery code or the session secret.
	req, _ = http.NewRequest("POST", "http://"+si.Addr+"/v1/root/init", nil)
	req.Header.Set("Authorization", "Bearer "+si.Secret)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("init: %v %v", resp, err)
	}
	var ir struct {
		RecoveryCode string `json:"recovery_code"`
	}
	json.NewDecoder(resp.Body).Decode(&ir)
	resp.Body.Close()
	if ir.RecoveryCode == "" {
		t.Fatal("no recovery code in the init response")
	}
	seed, err := os.ReadFile(filepath.Join(cfg, "parley", "root.key"))
	if err != nil {
		t.Fatal(err)
	}
	for name, stream := range map[string]string{"stdout": out.String(), "stderr": errw.String()} {
		for what, secret := range map[string]string{
			"recovery code": ir.RecoveryCode, "session secret": si.Secret, "root seed": string(seed),
			"root seed base64": base64.StdEncoding.EncodeToString(seed), "root seed hex": hex.EncodeToString(seed),
		} {
			if strings.Contains(stream, secret) {
				t.Errorf("%s carries the %s", name, what)
			}
		}
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, errw.String())
	}
	if _, err := os.Stat(info); err == nil {
		t.Error("info file left behind")
	}
}

func TestSignerCommandErrors(t *testing.T) {
	cfg := t.TempDir()
	dir := func() (string, error) { return cfg, nil }
	ctx := context.Background()
	// A non-empty directory at the info path can be neither removed nor replaced.
	busy := filepath.Join(cfg, "busy")
	os.MkdirAll(busy, 0o700)
	os.WriteFile(filepath.Join(busy, "f"), nil, 0o600)
	for name, args := range map[string][]string{
		"public address": {"signer", "-listen", "0.0.0.0:0"},
		"bad flag":       {"signer", "-nope"},
		"info is a dir":  {"signer", "-info", busy},
	} {
		var out, errw bytes.Buffer
		if code := runCtx(ctx, args, &out, &errw, dir); code == 0 || errw.Len() == 0 {
			t.Errorf("%s: code %d err %q", name, code, errw.String())
		}
	}
	// The info path's parent cannot be created.
	blocker := filepath.Join(cfg, "blocker")
	os.WriteFile(blocker, nil, 0o600)
	var out, errw bytes.Buffer
	if code := runCtx(ctx, []string{"signer", "-info", filepath.Join(blocker, "x", "s.json")}, &out, &errw, dir); code != 1 {
		t.Errorf("unwritable info: %d", code)
	}
	if code := runCtx(ctx, []string{"signer"}, &out, &errw, func() (string, error) { return "", errors.New("no home") }); code != 1 {
		t.Errorf("no config dir: %d", code)
	}
}

// syncBuffer is a bytes.Buffer safe to read while the signer goroutine writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
