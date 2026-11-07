// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package fsowner

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Inspect reports the owner (from the security descriptor) and the kind of file. Windows ACLs are not read:
// GroupOrOtherWrite and WorldWrite stay false, so on Windows the check is ownership by the current user (or the
// system, for parents). "Ours" is owned by the user or by the owner new files get from this process (the
// Administrators group for an elevated token). install.ps1 puts programs under the user's profile, whose ACL grants only the user, SYSTEM
// and Administrators.
func Inspect(path string) (Info, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return Info{}, err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return Info{}, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return Info{}, err
	}
	tok := windows.GetCurrentProcessToken()
	me, err := tok.GetTokenUser()
	if err != nil {
		return Info{}, err
	}
	def, buf, err := defaultOwner(tok)
	if err != nil {
		return Info{}, err
	}
	defer runtime.KeepAlive(buf)
	return Info{
		IsDir:     fi.IsDir(),
		IsRegular: fi.Mode().IsRegular(),
		Owned:     windows.EqualSid(owner, me.User.Sid) || windows.EqualSid(owner, def),
		Trusted:   owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid),
	}, nil
}

// defaultOwner is the owner new files get from this process: the user, or Administrators for an elevated token.
// The SID points into the returned buffer, which the caller keeps alive while using it.
func defaultOwner(tok windows.Token) (*windows.SID, []byte, error) {
	var n uint32
	windows.GetTokenInformation(tok, windows.TokenOwner, nil, 0, &n) // reports the size needed
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenOwner, &buf[0], n, &n); err != nil {
		return nil, nil, err
	}
	return (*struct{ Owner *windows.SID })(unsafe.Pointer(&buf[0])).Owner, buf, nil
}
