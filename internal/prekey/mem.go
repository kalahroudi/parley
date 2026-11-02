// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package prekey

import "fmt"

// Platform hooks (mem_unix.go, mem_windows.go), swappable so tests can drive
// every failure path on every OS.
var (
	mapRegion   = sysMap
	lockRegion  = sysLock
	unmapRegion = sysUnmap
)

// allocRegion maps n bytes outside the Go heap and locks them in RAM. If the
// lock fails it either returns ErrNotLocked (and unmaps) or, with
// allowUnlocked, hands back the unlocked region and locked=false so the caller
// knows what guarantee it has.
func allocRegion(n int, allowUnlocked bool) (mem []byte, locked bool, err error) {
	b, err := mapRegion(n)
	if err != nil {
		return nil, false, err
	}
	if err := lockRegion(b); err != nil {
		if !allowUnlocked {
			unmapRegion(b)
			return nil, false, fmt.Errorf("%w: %w", ErrNotLocked, err)
		}
		return b, false, nil
	}
	return b, true, nil
}

// freeRegion zeroes, unlocks and unmaps the region.
func freeRegion(b []byte) { unmapRegion(b) }
