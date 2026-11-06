// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package botproc

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLookupOfThisProcess(t *testing.T) {
	in, err := lookup(os.Getpid())
	if err != nil || in.ppid != os.Getppid() || len(in.groups) != 1 || in.groups[0] <= 0 {
		t.Errorf("%+v %v", in, err)
	}
}

func TestLookupFailsWhenTheSystemRefuses(t *testing.T) {
	old := kinfoProc
	defer func() { kinfoProc = old }()
	kinfoProc = func(string, ...int) (*unix.KinfoProc, error) { return nil, errors.New("refused") }
	if _, err := lookup(os.Getpid()); err == nil {
		t.Error("a refusal was taken for an answer")
	}
}

func TestLookupOfAnEmptyAnswerIsNoProcess(t *testing.T) {
	old := kinfoProc
	defer func() { kinfoProc = old }()
	kinfoProc = func(string, ...int) (*unix.KinfoProc, error) { return &unix.KinfoProc{}, nil }
	if _, err := lookup(os.Getpid()); !errors.Is(err, ErrUnknown) {
		t.Errorf("%v", err)
	}
}
