// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package acceptance

// openSockets: a child process on Windows inherits only the handles Go passes
// explicitly (none here), so there is nothing to list.
func openSockets() []int { return nil }
