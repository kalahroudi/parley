// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kalahroudi/parley/internal/root"
)

// adminInit creates the tenant signing root: the key goes to the store, the
// encrypted backup to a file, and the recovery code is printed once.
func adminInit(args []string, out, errw io.Writer, store root.Store, defaultBackup string) int {
	fs := flag.NewFlagSet("admin init", flag.ContinueOnError)
	fs.SetOutput(errw)
	backupPath := fs.String("backup", defaultBackup, "where to write the encrypted root backup")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if exists, err := store.Exists(); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	} else if exists {
		fmt.Fprintln(errw, "error:", root.ErrExists)
		return 1
	}
	r, err := root.New()
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(*backupPath), 0o700); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	if err := os.WriteFile(*backupPath, r.Backup, 0o600); err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	if err := store.Save(r.Private); err != nil {
		os.Remove(*backupPath)
		if errors.Is(err, root.ErrExists) {
			fmt.Fprintln(errw, "error:", err)
		} else {
			fmt.Fprintln(errw, "error: saving root key:", err)
		}
		return 1
	}
	fmt.Fprintf(out, "Root created.\n\nFingerprint: %s\nRecovery code: %s\nBackup file: %s\n\n", r.Fingerprint, r.RecoveryCode, *backupPath)
	fmt.Fprintln(out, "Write the recovery code down now; it is shown only once and cannot be recovered.")
	fmt.Fprintln(out, "Share the fingerprint with your users through a channel other than Parley (chat or email).")
	return 0
}
