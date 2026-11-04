// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package fsperm

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// withSDDL makes the next access-list reads see the given descriptor (SDDL),
// so each rule can be tested without changing a real directory's permissions.
func withSDDL(t *testing.T, sddl string) {
	t.Helper()
	old := securityOf
	securityOf = func(string) (*windows.SECURITY_DESCRIPTOR, error) { return windows.SecurityDescriptorFromString(sddl) }
	t.Cleanup(func() { securityOf = old })
}

func TestCheckACLRules(t *testing.T) {
	p := privateFile(t)
	user, err := tokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := user.User.Sid.String()
	cases := []struct {
		name, sddl string
		ok         bool
	}{
		{"owner and a private acl", "O:" + me + "D:P(A;;FA;;;" + me + ")", true},
		{"administrators own it", "O:BAD:P(A;;FA;;;BA)", true},
		{"a deny entry is ignored", "O:" + me + "D:P(D;;FA;;;BG)(A;;FA;;;" + me + ")", true},
		{"no owner", "D:P(A;;FA;;;BA)", false},
		{"owned by SYSTEM", "O:SYD:P(A;;FA;;;SY)", false},
		{"no acl at all", "O:BA", false},
		{"everyone", "O:BAD:P(A;;FA;;;WD)", false},
		{"users", "O:BAD:P(A;;FA;;;BU)", false},
		{"authenticated users", "O:BAD:P(A;;FA;;;AU)", false},
		{"exposed entry after a private one", "O:BAD:P(A;;FA;;;BA)(A;;FR;;;WD)", false},
	}
	for _, c := range cases {
		withSDDL(t, c.sddl)
		for what, err := range map[string]error{"dir": CheckDir(filepath.Dir(p)), "file": CheckFile(p)} {
			if (err == nil) != c.ok {
				t.Errorf("%s (%s): ok=%v, got %v", c.name, what, c.ok, err)
			}
		}
	}
}

func TestCheckACLFailures(t *testing.T) {
	p := privateFile(t)
	boom := errors.New("boom")

	old := securityOf
	securityOf = func(string) (*windows.SECURITY_DESCRIPTOR, error) { return nil, boom }
	if err := CheckFile(p); !errors.Is(err, boom) {
		t.Errorf("unreadable access list: %v", err)
	}
	securityOf = old

	oldTok := tokenUser
	tokenUser = func() (*windows.Tokenuser, error) { return nil, boom }
	if err := CheckFile(p); !errors.Is(err, boom) {
		t.Errorf("no current user (check): %v", err)
	}
	if err := EnsureDir(filepath.Join(tempDir(t), "new")); !errors.Is(err, boom) {
		t.Errorf("no current user (create): %v", err)
	}
	tokenUser = oldTok

	oldAce := aceAt
	aceAt = func(*windows.ACL, uint32, **windows.ACCESS_ALLOWED_ACE) error { return boom }
	if err := CheckFile(p); !errors.Is(err, boom) {
		t.Errorf("unreadable entry: %v", err)
	}
	aceAt = oldAce
}

func TestEnsureDirFailures(t *testing.T) {
	boom := errors.New("boom")
	base := tempDir(t)
	if err := EnsureDir(filepath.Join(base, "bad\x00name")); err == nil {
		t.Error("a path with a NUL was accepted")
	}
	old := parseSDDL
	parseSDDL = func(string) (*windows.SECURITY_DESCRIPTOR, error) { return nil, boom }
	if err := EnsureDir(filepath.Join(base, "a")); !errors.Is(err, boom) {
		t.Errorf("bad access list: %v", err)
	}
	parseSDDL = old
	oldCreate := createDir
	createDir = func(*uint16, *windows.SecurityAttributes) error { return boom }
	if err := EnsureDir(filepath.Join(base, "b")); !errors.Is(err, boom) {
		t.Errorf("create failure: %v", err)
	}
	createDir = oldCreate
}

func TestEnsureDirUnderAFile(t *testing.T) {
	f := privateFile(t)
	if err := EnsureDir(filepath.Join(f, "sub", "dir")); err == nil {
		t.Error("a directory under a file was created")
	}
}

func TestTrustedOwnerAndExposed(t *testing.T) {
	user, _ := tokenUser()
	sid := func(s string) *windows.SID { x, _ := windows.StringToSid(s); return x }
	if !trustedOwner(user.User.Sid, user.User.Sid) || !trustedOwner(sid("S-1-5-32-544"), user.User.Sid) {
		t.Error("the user and Administrators are trusted owners")
	}
	if trustedOwner(sid("S-1-5-18"), user.User.Sid) || trustedOwner(nil, user.User.Sid) {
		t.Error("SYSTEM and no owner are not trusted")
	}
	for _, s := range []string{"S-1-1-0", "S-1-5-32-545", "S-1-5-11"} {
		if !exposed(sid(s)) {
			t.Errorf("%s must count as exposed", s)
		}
	}
	if exposed(sid("S-1-5-18")) || exposed(user.User.Sid) {
		t.Error("SYSTEM and the user are not exposed")
	}
}
