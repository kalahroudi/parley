// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package fsowner reports who owns a path and who can write it, for the updater's install-directory check
// (internal/update). It is the operating-system glue; the decision is made in internal/update.
package fsowner

// Info is what the owner check needs to know about one path. Inspect never follows a final link.
type Info struct {
	IsDir, IsRegular  bool
	Owned             bool // owned by the user running this process
	Trusted           bool // owned by the system (root, SYSTEM, Administrators): fine as a parent of the install directory
	GroupOrOtherWrite bool // writable by the group or by everyone (Unix mode bits; on Windows, an allow entry for Everyone, Users or Authenticated Users that writes)
	WorldWrite        bool // entries can be removed, renamed or the access list changed by everyone (Windows: delete, delete-child, change permissions or owner, generic write/all)
	Sticky            bool // only the owner of an entry may remove or rename it
	Setid             bool // setuid or setgid (Unix): replacing the file would silently drop the bit
}
