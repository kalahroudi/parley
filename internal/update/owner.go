// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kalahroudi/parley/internal/fsowner"
)

// ErrNotOwner means the install directory or one of its programs belongs to someone other than the user running
// the update, or can be changed by others. The updater then replaces nothing: a process must never write programs
// into a place another user controls (they could swap the file between the check and the rename, or a root process
// would be tricked into running their code at the next start), and it must never write into a place another
// user owns on its own authority.
var ErrNotOwner = errors.New("update: the install directory is not owned by the current user or is writable by others; not replacing programs there")

// checkInstall decides whether the updater may replace the programs files inside dir. All of this must hold:
//
//   - dir is a directory owned by the current user and not writable by group or others;
//   - every parent of dir (links resolved) is owned by the current user or the system, and none is writable by
//     everyone unless it has the sticky bit (like /tmp), so nobody else can rename a parent away and put their
//     own tree in its place;
//   - each program is a regular file (not a link), owned by the current user, not writable by group or others,
//     and not setuid or setgid (a replacement would silently lose the bit).
//
// Because "the current user" is the effective user of this process, a root process refuses a directory owned by
// someone else and a user process refuses one owned by root: an update never runs as another user than the one
// the install belongs to.
func checkInstall(dir string, files []string, inspect func(string) (fsowner.Info, error)) error {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	di, err := inspect(real)
	if err != nil {
		return err
	}
	if !di.IsDir || !di.Owned || di.GroupOrOtherWrite {
		return fmt.Errorf("%w: %s", ErrNotOwner, real)
	}
	for p := filepath.Dir(real); ; p = filepath.Dir(p) {
		pi, err := inspect(p)
		if err != nil {
			return err
		}
		// Group write counts too, unless the system owns the parent (like /Library on macOS): a group member could
		// rename our directory away. A sticky parent only lets the owner of an entry rename it.
		if !(pi.Owned || pi.Trusted) || !pi.Sticky && (pi.WorldWrite || pi.GroupOrOtherWrite && !pi.Trusted) {
			return fmt.Errorf("%w: parent %s (%+v)", ErrNotOwner, p, pi)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	for _, f := range files {
		fi, err := inspect(filepath.Join(real, filepath.Base(f)))
		if err != nil {
			return err
		}
		if !fi.IsRegular || !fi.Owned || fi.GroupOrOtherWrite || fi.Setid {
			return fmt.Errorf("%w: %s", ErrNotOwner, filepath.Base(f))
		}
	}
	return nil
}

// checkOwner runs checkInstall for the programs that exist in Dir and returns their names and the directory
// with links resolved: the caller writes there, not through the path it was given, so a link swapped later
// cannot redirect the writes. The first name must exist; a missing optional one is skipped. A directory a
// package manager owns is refused first, with the way to update it.
func (u *Updater) checkOwner() (names []string, dir string, err error) {
	inspect := u.inspect
	if inspect == nil {
		inspect = fsowner.Inspect
	}
	dir, err = filepath.EvalSymlinks(u.Dir)
	if err != nil {
		return nil, "", err
	}
	if managed(filepath.Join(dir, "x")) {
		return nil, "", ErrManaged
	}
	var files []string
	for i, name := range u.Names {
		dst := filepath.Join(dir, name+exeSuffix(u.OS))
		if _, err := os.Lstat(dst); err != nil {
			if i == 0 {
				return nil, "", err
			}
			continue
		}
		names, files = append(names, name), append(files, dst)
	}
	return names, dir, checkInstall(dir, files, inspect)
}
