// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package ttydev opens the process's controlling terminal: /dev/tty on Linux and macOS, the console (CONIN$ and
// CONOUT$) on Windows. It fails when the process has none. It is split from ttyconfirm so that the operating-system
// part is separate from the decision of what counts as an answer.
package ttydev
