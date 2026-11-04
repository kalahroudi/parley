// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package daemon

import (
	"fmt"
	"os"
	"syscall"
)

// geteuid is a seam so tests can exercise the wrong-owner paths.
var geteuid = os.Geteuid

// ensurePrivateDir creates dir (0700) if needed and then verifies it: a real
// directory, owned by this user, closed to group and others. Anything else
// stops startup, so a directory someone else can write to never holds the
// socket or the keys.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("daemon: create %s: %w", dir, err)
	}
	return checkPrivateDir(dir)
}

func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("daemon: %s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != geteuid() {
		return fmt.Errorf("daemon: %s is not owned by the current user", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("daemon: %s is accessible to other users (mode %o); run chmod 700", dir, fi.Mode().Perm())
	}
	return nil
}

// checkPrivateFile fails unless path is a regular file (not a symlink) owned by
// this user and closed to group and others.
func checkPrivateFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || int(st.Uid) != geteuid() {
		return fmt.Errorf("daemon: %s is not a regular file owned by the current user", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("daemon: %s is accessible to other users (mode %o); run chmod 600", path, fi.Mode().Perm())
	}
	return nil
}
