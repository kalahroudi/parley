// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"path/filepath"
	"strings"
)

// Locate returns the directory of the executable exe after resolving links, or ErrManaged when a package
// manager owns it (Homebrew, apt and the like): replacing those files would fight the package manager and leave
// its records wrong, so they are updated with it.
func Locate(exe string) (string, error) {
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	if managed(real) {
		return "", ErrManaged
	}
	return filepath.Dir(real), nil
}

func managed(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	for _, part := range []string{"/cellar/", "/homebrew/", "/linuxbrew/", "/nix/store/", "/snap/", "/program files/", "/program files (x86)/", "/windowsapps/"} {
		if strings.Contains(p, part) {
			return true
		}
	}
	for _, prefix := range []string{"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}
