// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"errors"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// maxName is the gateway's limit on a device name, counted in UTF-16 code units like its check.
const maxName = 100

// ErrBadName means the device name would be refused by the gateway.
var ErrBadName = errors.New("enroll: device name must be 1-100 characters of printable text (no control, format, separator or private-use characters, and no whitespace but a plain space)")

// ValidName applies the same rules as the gateway's display-text check, so a
// name that passes here is not refused there: not empty, at most maxName
// characters, valid UTF-8, no control, format, line/paragraph separator or
// private-use characters, and no whitespace except a plain space. The gateway
// also trims it, so leading and trailing spaces are refused here instead of
// silently changed.
func ValidName(s string) error {
	if s == "" || !utf8.ValidString(s) || s[0] == ' ' || s[len(s)-1] == ' ' {
		return ErrBadName
	}
	units := 0
	for _, r := range s {
		units += len(utf16.Encode([]rune{r}))
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Co) || (unicode.IsSpace(r) && r != ' ') {
			return ErrBadName
		}
	}
	if units > maxName {
		return ErrBadName
	}
	return nil
}
