// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !windows

package prekey

// markUndumpable: macOS has no prctl; RLIMIT_CORE=0 and the hardened runtime
// (no get-task-allow, set at signing time) cover it.
func markUndumpable() error { return nil }
