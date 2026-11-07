// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package releasekey holds the project's release verification key, compiled into every binary. Updates are
// accepted only when signed by this key; nothing fetched at run time can replace it.
package releasekey

import _ "embed"

//go:embed release.pub
var public []byte

// Public returns the minisign public key file that release artifacts must be signed with.
func Public() []byte { return append([]byte(nil), public...) }
