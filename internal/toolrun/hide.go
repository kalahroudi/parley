// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package toolrun

import "path/filepath"

// existingDirs returns the resolved absolute paths of the directories among dirs that exist; one that does not exist
// has nothing to hide.
func existingDirs(dirs []string) []string {
	var out []string
	for _, d := range dirs {
		if r, err := absDir(d); err == nil && filepath.IsAbs(r) {
			out = append(out, r)
		}
	}
	return out
}
