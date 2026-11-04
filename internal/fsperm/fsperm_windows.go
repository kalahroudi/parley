// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package fsperm

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Win32 calls that cannot be made to fail on a healthy machine are seams,
// so tests can exercise every error path.
var (
	tokenUser  = func() (*windows.Tokenuser, error) { return windows.GetCurrentProcessToken().GetTokenUser() }
	parseSDDL  = windows.SecurityDescriptorFromString
	createDir  = windows.CreateDirectory
	securityOf = func(path string) (*windows.SECURITY_DESCRIPTOR, error) {
		return windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	}
	aceAt = windows.GetAce
)

// EnsureDir creates dir with a protected DACL (no inheritance) that grants full
// control to the current user, SYSTEM and Administrators only, then verifies it.
// An existing directory is only verified, never re-permissioned.
func EnsureDir(dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return CheckDir(dir)
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return fmt.Errorf("fsperm: bad path: %w", err)
	}
	u, err := tokenUser()
	if err != nil {
		return fmt.Errorf("fsperm: current user: %w", err)
	}
	sd, err := parseSDDL("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + u.User.Sid.String() + ")")
	if err != nil {
		return fmt.Errorf("fsperm: build access list: %w", err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	// Parents are created normally; only the leaf holds secrets.
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return fmt.Errorf("fsperm: create %s: %w", dir, err)
	}
	if err := createDir(p, &sa); err != nil {
		return fmt.Errorf("fsperm: create %s: %w", dir, err)
	}
	return CheckDir(dir)
}

// CheckDir fails unless dir is a real directory (not a symlink or junction)
// owned by the current user (or Administrators) whose DACL grants nothing to
// Everyone, Users or Authenticated Users.
func CheckDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("fsperm: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("fsperm: %s is not a directory", dir)
	}
	return checkACL(dir)
}

// CheckFile fails unless path is a regular file (not a symlink) that passes the
// same owner and DACL checks as a directory. A missing file is an error
// satisfying errors.Is(err, os.ErrNotExist).
func CheckFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("fsperm: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("fsperm: %s is not a regular file", path)
	}
	return checkACL(path)
}

func checkACL(path string) error {
	sd, err := securityOf(path)
	if err != nil {
		return fmt.Errorf("fsperm: read access list of %s: %w", path, err)
	}
	u, err := tokenUser()
	if err != nil {
		return fmt.Errorf("fsperm: current user: %w", err)
	}
	owner, _, _ := sd.Owner()
	if !trustedOwner(owner, u.User.Sid) {
		return fmt.Errorf("fsperm: %s is not owned by the current user", path)
	}
	dacl, _, _ := sd.DACL()
	if dacl == nil {
		return fmt.Errorf("fsperm: %s has no access list (open to everyone)", path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := aceAt(dacl, i, &ace); err != nil {
			return fmt.Errorf("fsperm: read access list of %s: %w", path, err)
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && exposed((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return fmt.Errorf("fsperm: %s is accessible to other users", path)
		}
	}
	return nil
}

// trustedOwner: the current user or Administrators (what an elevated process creates).
func trustedOwner(owner, user *windows.SID) bool {
	return owner != nil && (owner.Equals(user) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

// exposed reports whether sid is a group that includes other users.
func exposed(sid *windows.SID) bool {
	return sid.IsWellKnown(windows.WinWorldSid) || sid.IsWellKnown(windows.WinBuiltinUsersSid) || sid.IsWellKnown(windows.WinAuthenticatedUserSid)
}
