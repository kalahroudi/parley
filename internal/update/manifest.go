// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A release's signed comment is its manifest header:
//
//	parley release vMAJOR.MINOR.PATCH issued=<unix seconds> expires=<unix seconds>
//
// It is covered by the signature, so a mirror cannot extend it. The expiry is what lets a device notice a frozen
// feed: a mirror that withholds new releases can only replay a manifest until it expires.
const (
	maxSkew     = 5 * time.Minute      // clock difference tolerated for "issued in the future"
	maxValidity = 400 * 24 * time.Hour // the longest window a manifest may claim
	maxUnix     = 1 << 40              // a sane bound on a timestamp (year 36000)
)

var (
	// ErrExpired means the manifest's validity ended: the feed is stale or was frozen, or the project must re-sign.
	ErrExpired = errors.New("update: release manifest has expired")
	// ErrNotYetValid means the manifest claims to be issued in the future (beyond clock skew).
	ErrNotYetValid = errors.New("update: release manifest is not valid yet")
)

// Manifest is the parsed header of a release's signed comment.
type Manifest struct {
	Version Version
	Issued  time.Time
	Expires time.Time
}

// FormatComment renders the signed comment for a release; scripts/release.sh builds the same text.
func FormatComment(v Version, issued, expires time.Time) string {
	return fmt.Sprintf("%s%s issued=%d expires=%d", commentIs, v, issued.Unix(), expires.Unix())
}

// ParseComment reads a signed comment strictly: only the canonical text FormatComment writes is accepted.
func ParseComment(c string) (Manifest, error) {
	bad := fmt.Errorf("%w: unexpected signed comment", ErrSignature)
	f := strings.Split(strings.TrimPrefix(c, commentIs), " ")
	if len(f) != 3 || !strings.HasPrefix(c, commentIs) {
		return Manifest{}, bad
	}
	v, err := ParseVersion(f[0])
	if err != nil {
		return Manifest{}, bad
	}
	issued, ok := unixField(f[1], "issued=")
	if !ok {
		return Manifest{}, bad
	}
	expires, ok := unixField(f[2], "expires=")
	if !ok {
		return Manifest{}, bad
	}
	m := Manifest{Version: v, Issued: issued, Expires: expires}
	if c != FormatComment(m.Version, m.Issued, m.Expires) { // not the canonical spelling
		return Manifest{}, bad
	}
	return m, nil
}

func unixField(s, key string) (time.Time, bool) {
	digits, ok := strings.CutPrefix(s, key)
	if !ok {
		return time.Time{}, false
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	if n < 0 || n > maxUnix {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

// checkValidity applies the window at now. A window that ends before it starts, or is longer than maxValidity, is
// malformed rather than merely expired.
func (m Manifest) checkValidity(now time.Time) error {
	if !m.Expires.After(m.Issued) || m.Expires.Sub(m.Issued) > maxValidity {
		return fmt.Errorf("%w: unreasonable validity window", ErrSignature)
	}
	if m.Issued.After(now.Add(maxSkew)) {
		return ErrNotYetValid
	}
	if !now.Before(m.Expires) {
		return ErrExpired
	}
	return nil
}
