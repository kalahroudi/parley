// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package prekey

// quiesce is a no-op off Linux: there is no portable way to hold off the
// runtime's preemption signals, so a signal that lands while the scalar is in
// a register can leave a copy in the signal stack (see quiesce_linux.go).
func quiesce() (restore func()) { return func() {} }
