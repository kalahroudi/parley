// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package fsowner

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Inspect reports the owner and the access list (from the security descriptor) and the kind of file. "Ours" is
// owned by the user or by the owner new files get from this process (the Administrators group for an elevated
// token). GroupOrOtherWrite and WorldWrite come from the allow entries for Everyone, Users and Authenticated
// Users that apply to the object itself (entries that only pass to children are skipped), the same groups
// fsperm treats as other users. A missing access list is open to everyone.
func Inspect(path string) (Info, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return Info{}, err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
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
	any, strong, err := othersWrite(sd)
	if err != nil {
		return Info{}, err
	}
	trusted := owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.Equals(trustedInstaller)
	return Info{
		IsDir:     fi.IsDir(),
		IsRegular: fi.Mode().IsRegular(),
		Owned:     windows.EqualSid(owner, me.User.Sid) || windows.EqualSid(owner, def),
		Trusted:   trusted,

		GroupOrOtherWrite: any,
		WorldWrite:        strong && !trusted, // what the system owns keeps the access list the system gave it (C:\ itself lets Users add entries)
	}, nil
}

// trustedInstaller (NT SERVICE\TrustedInstaller) owns the system's own files and folders on current Windows.
var trustedInstaller = func() *windows.SID {
	sid, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	if err != nil {
		panic(err)
	}
	return sid
}()

// Access rights that let others change a file's contents (dataWrite) or take it over, delete it or its entries
// (takeOver). Creating a subdirectory in a parent (FILE_APPEND_DATA alone is not enough to rename an entry away)
// is deliberately not takeOver.
const (
	dataWrite   = 0x2 | 0x4 | 0x10000 | 0x40000000                             // FILE_WRITE_DATA, FILE_APPEND_DATA, DELETE, GENERIC_WRITE
	takeOver    = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000 // FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE
	inheritOnly = 0x08
)

// othersWrite reads the access list: any is true when Everyone, Users or Authenticated Users are allowed to write
// or take over the object, strong when they may delete it or its entries or change its permissions.
func othersWrite(sd *windows.SECURITY_DESCRIPTOR) (any, strong bool, err error) {
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, false, err
	}
	if dacl == nil {
		return true, true, nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, false, err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&inheritOnly != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !(sid.IsWellKnown(windows.WinWorldSid) || sid.IsWellKnown(windows.WinBuiltinUsersSid) || sid.IsWellKnown(windows.WinAuthenticatedUserSid)) {
			continue
		}
		strong = strong || uint32(ace.Mask)&takeOver != 0
		any = any || uint32(ace.Mask)&(takeOver|dataWrite) != 0
	}
	return any, strong, nil
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
