// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package botproc

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

func fakeProc(t *testing.T, pid int, stat string) {
	t.Helper()
	root := t.TempDir()
	if stat != "" {
		if err := os.MkdirAll(filepath.Join(root, strconv.Itoa(pid)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, strconv.Itoa(pid), "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

func TestLookupReadsParentGroupAndSession(t *testing.T) {
	// The name may hold spaces and parentheses; the fields are counted from the last ')'.
	fakeProc(t, 77, "77 (we ird) name) S 12 34 56 0 -1 4194560 100 0")
	in, err := lookup(77)
	if err != nil || in.ppid != 12 || !slices.Equal(in.groups, []int{34, 56}) {
		t.Errorf("%+v %v", in, err)
	}
}

// The edges of the format that are still valid: the shortest line with four fields after the name, and a name that is empty.
func TestLookupAcceptsTheShortestValidLines(t *testing.T) {
	for stat, want := range map[string]info{
		"77 (a) S 1 2 3": {ppid: 1, groups: []int{2, 3}},
		") S 4 5 6":      {ppid: 4, groups: []int{5, 6}}, // the closing parenthesis is the first byte
	} {
		fakeProc(t, 77, stat)
		in, err := lookup(77)
		if err != nil || in.ppid != want.ppid || !slices.Equal(in.groups, want.groups) {
			t.Errorf("%q: %+v %v, want %+v", stat, in, err, want)
		}
	}
}

func TestLookupRefusesWhatItCannotRead(t *testing.T) {
	for name, stat := range map[string]string{
		"no such process":  "",
		"no closing paren": "77 name S 1 2 3",
		"too few fields":   "77 (a) S 1 2",
		"bad parent":       "77 (a) S x 2 3 4",
		"bad group":        "77 (a) S 1 x 3 4",
		"bad session":      "77 (a) S 1 2 x 4",
	} {
		fakeProc(t, 77, stat)
		if _, err := lookup(77); err == nil {
			t.Errorf("%s: accepted", name)
		} else if name != "no such process" && !errors.Is(err, ErrUnknown) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLookupOfThisProcess(t *testing.T) {
	in, err := lookup(os.Getpid())
	if err != nil || in.ppid != os.Getppid() || len(in.groups) != 2 {
		t.Errorf("%+v %v", in, err)
	}
}
