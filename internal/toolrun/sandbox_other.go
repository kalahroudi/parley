// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package toolrun

// There is no sandbox here to confine a tool with, so New refuses: no tool runs.
func findSandbox([]string) (boxer, error) { return nil, ErrNoSandbox }
