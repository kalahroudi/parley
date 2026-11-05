// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package fsperm

// syncDir does nothing: Windows cannot open or sync directories.
func syncDir(string) error { return nil }
