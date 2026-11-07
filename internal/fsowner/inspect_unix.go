// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package fsowner

import (
	"os"
	"syscall"
)

// Inspect reports owner and mode bits from lstat (it never follows a link).
func Inspect(path string) (Info, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return Info{}, err
	}
	st := fi.Sys().(*syscall.Stat_t) // always a Stat_t on Unix
	m := fi.Mode()
	return Info{
		IsDir:             m.IsDir(),
		IsRegular:         m.IsRegular(),
		Owned:             int(st.Uid) == os.Geteuid(),
		Trusted:           st.Uid == 0,
		GroupOrOtherWrite: m.Perm()&0o022 != 0,
		WorldWrite:        m.Perm()&0o002 != 0,
		Sticky:            m&os.ModeSticky != 0,
		Setid:             m&(os.ModeSetuid|os.ModeSetgid) != 0,
	}, nil
}
