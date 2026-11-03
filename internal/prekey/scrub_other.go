// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !amd64 && !arm64

package prekey

// scrubVectorRegisters has no implementation on this architecture; the
// guarantee is weaker there (see the package comment).
func scrubVectorRegisters() {}
