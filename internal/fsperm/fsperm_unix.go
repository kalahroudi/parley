// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package fsperm

import (
	"fmt"
	"os"
	"syscall"
)

// geteuid is a seam so tests can exercise the wrong-owner paths.
var geteuid = os.Geteuid

// EnsureDir creates dir (0700) if needed and then verifies it with CheckDir.
// Anything wrong stops startup, so a directory someone else can write to never
// holds the socket or the keys.
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("fsperm: create %s: %w", dir, err)
	}
	return CheckDir(dir)
}

// CheckDir fails unless dir is a real directory (not a symlink), owned by this
// user and closed to group and others.
func CheckDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("fsperm: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("fsperm: %s is not a directory", dir)
	}
	return checkPrivate(fi, dir)
}

// CheckFile fails unless path is a regular file (not a symlink) owned by this
// user and closed to group and others. A missing file is an error satisfying
// errors.Is(err, os.ErrNotExist).
func CheckFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("fsperm: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("fsperm: %s is not a regular file", path)
	}
	return checkPrivate(fi, path)
}

func checkPrivate(fi os.FileInfo, path string) error {
	if int(fi.Sys().(*syscall.Stat_t).Uid) != geteuid() {
		return fmt.Errorf("fsperm: %s is not owned by the current user", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("fsperm: %s is accessible to other users (mode %o); remove group and other access", path, fi.Mode().Perm())
	}
	return nil
}
