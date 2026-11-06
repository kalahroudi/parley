// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ttydev

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

type console struct {
	io.Reader
	io.Writer
}

// Open opens the process's console input and output, which exist only when the process is attached to a
// console. Both handles are checked to be consoles, so a redirected handle is not accepted.
//
//cover:ignore needs a console, which a CI runner does not have; the refusal without one is tested by ttyconfirm
func Open() (io.ReadWriter, func(), error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		in.Close()
		return nil, nil, err
	}
	var mode uint32
	if windows.GetConsoleMode(windows.Handle(in.Fd()), &mode) != nil || windows.GetConsoleMode(windows.Handle(out.Fd()), &mode) != nil {
		in.Close()
		out.Close()
		return nil, nil, errors.New("not a console")
	}
	return console{in, out}, func() { in.Close(); out.Close() }, nil
}
