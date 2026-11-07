// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package update is the daemon's self-update. It trusts exactly one thing: the project's release key, pinned in
// the binary. The transport (GitHub, a mirror) is untrusted; a release is installed only when its SHA256SUMS file
// carries a valid signature from that key whose signed comment names the version, and each binary matches the
// signed checksum. It never moves to an older version on its own, and an operator can pin a version.
package update

import (
	"cmp"
	"errors"
	"strconv"
	"strings"
)

// Version is a release number, vMAJOR.MINOR.PATCH. Pre-release and build suffixes are not release versions.
type Version struct{ Major, Minor, Patch uint32 }

// ErrVersion means a string is not a release version.
var ErrVersion = errors.New("update: not a release version (want vMAJOR.MINOR.PATCH)")

// ParseVersion accepts "v1.2.3" and "1.2.3". Each part is decimal digits without leading zeros, at most nine.
func ParseVersion(s string) (Version, error) {
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) != 3 {
		return Version{}, ErrVersion
	}
	var n [3]uint32
	for i, p := range parts {
		if p == "" || len(p) > 9 || (len(p) > 1 && p[0] == '0') {
			return Version{}, ErrVersion
		}
		for j := 0; j < len(p); j++ {
			if p[j] < '0' || p[j] > '9' {
				return Version{}, ErrVersion
			}
		}
		v, _ := strconv.ParseUint(p, 10, 32) // at most nine digits
		n[i] = uint32(v)
	}
	return Version{n[0], n[1], n[2]}, nil
}

// String is the canonical form, with the leading v used in release tags and file names.
func (v Version) String() string {
	return "v" + strconv.FormatUint(uint64(v.Major), 10) + "." + strconv.FormatUint(uint64(v.Minor), 10) + "." + strconv.FormatUint(uint64(v.Patch), 10)
}

// Less reports whether v is older than o.
func (v Version) Less(o Version) bool {
	return cmp.Or(cmp.Compare(v.Major, o.Major), cmp.Compare(v.Minor, o.Minor), cmp.Compare(v.Patch, o.Patch)) < 0
}
