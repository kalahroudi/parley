// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package prekey

import "syscall"

// hardenSteps are run by Harden in order.
var hardenSteps = []func() error{zeroCoreLimit, markUndumpable}

func zeroCoreLimit() error { return setCoreLimit(&syscall.Rlimit{}) }

func setCoreLimit(l *syscall.Rlimit) error { return syscall.Setrlimit(syscall.RLIMIT_CORE, l) }
