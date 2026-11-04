// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ensurePrivateDir creates dir with a protected DACL (no inheritance) that
// grants full control to the current user, SYSTEM and Administrators only, then
// verifies it. An existing directory is only verified, never re-permissioned.
func ensurePrivateDir(dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return checkPrivateDir(dir)
	}
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("daemon: current user: %w", err)
	}
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + u.User.Sid.String() + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("daemon: build access list: %w", err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	// Parents are created normally; only the leaf holds secrets.
	if err := os.MkdirAll(parentOf(dir), 0o700); err != nil {
		return fmt.Errorf("daemon: create %s: %w", dir, err)
	}
	if err := windows.CreateDirectory(p, &sa); err != nil {
		return fmt.Errorf("daemon: create %s: %w", dir, err)
	}
	return checkPrivateDir(dir)
}

// checkPrivateDir fails if the directory's owner is not the current user (or
// Administrators) or if its DACL grants anything to Everyone, Users or
// Authenticated Users.
func checkPrivateDir(dir string) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("daemon: read access list of %s: %w", dir, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("daemon: read owner of %s: %w", dir, err)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("daemon: current user: %w", err)
	}
	if !owner.Equals(u.User.Sid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return fmt.Errorf("daemon: %s is not owned by the current user", dir)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("daemon: %s has no access list (open to everyone)", dir)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("daemon: read access list of %s: %w", dir, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, bad := range []windows.WELL_KNOWN_SID_TYPE{windows.WinWorldSid, windows.WinBuiltinUsersSid, windows.WinAuthenticatedUserSid} {
			if sid.IsWellKnown(bad) {
				return fmt.Errorf("daemon: %s is accessible to other users", dir)
			}
		}
	}
	return nil
}

func parentOf(dir string) string { return filepath.Dir(dir) }

// checkPrivateFile: the key file inherits the protected DACL of its directory,
// which ensurePrivateDir verified; Windows mode bits say nothing, so only a
// regular-file check is made (no reparse points).
func checkPrivateFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("daemon: %s is not a regular file", path)
	}
	return nil
}
