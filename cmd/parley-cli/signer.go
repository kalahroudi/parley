// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kalahroudi/parley/internal/fsperm"
	"github.com/kalahroudi/parley/internal/revocation"
	"github.com/kalahroudi/parley/internal/root"
	"github.com/kalahroudi/parley/internal/signer"
)

// signerInfo is what the dashboard's launcher reads to reach the signer. The
// file is 0600 in the 0700 config directory, so only this OS user can read the
// per-session secret.
type signerInfo struct {
	Addr   string `json:"addr"`
	Secret string `json:"secret"`
	PID    int    `json:"pid"`
}

// runSigner serves the local signer until ctx ends. Stdout gets one line with
// the address and never the secret.
func runSigner(ctx context.Context, args []string, out, errw io.Writer, dir string) int {
	fs := flag.NewFlagSet("signer", flag.ContinueOnError)
	fs.SetOutput(errw)
	listen := fs.String("listen", "127.0.0.1:0", "loopback address to listen on")
	infoPath := fs.String("info", filepath.Join(dir, "signer.json"), "where to write the address and session secret (0600)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// The config directory holds the root key and the session secret: it must be ours and closed to other users.
	for _, d := range []string{dir, filepath.Dir(*infoPath)} {
		if err := fsperm.EnsureDir(d); err != nil {
			fmt.Fprintln(errw, "error:", err)
			return 1
		}
	}
	secret := signer.NewSecret()
	s := &signer.Server{Store: root.FileStore{Dir: dir}, Revocations: revocation.NewFileStore(filepath.Join(dir, "revocations-issued.json")), BackupPath: filepath.Join(dir, "root-backup.json"), Secret: secret}
	l, err := s.Listen(*listen)
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	info, _ := json.Marshal(signerInfo{l.Addr().String(), secret, os.Getpid()})
	// Replace any stale file from a dead signer; the new file is created 0600.
	os.Remove(*infoPath)
	if err := writeNew(*infoPath, info); err != nil {
		l.Close()
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	defer os.Remove(*infoPath)
	fmt.Fprintln(out, "signer listening on", l.Addr())

	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	if err := srv.Serve(l); err != http.ErrServerClosed {
		//cover:ignore Serve on a healthy listener only returns after Close
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	return 0
}
