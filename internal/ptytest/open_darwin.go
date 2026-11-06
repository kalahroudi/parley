// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package ptytest

import (
	"bytes"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

func open() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	//cover:ignore a pseudo-terminal call that cannot fail on a healthy machine
	if err != nil {
		return nil, nil, err
	}
	fd := int(master.Fd())
	var name [128]byte
	for _, step := range []func() error{
		func() error { return ioctl(fd, unix.TIOCPTYGRANT, nil) },
		func() error { return ioctl(fd, unix.TIOCPTYUNLK, nil) },
		func() error { return ioctl(fd, unix.TIOCPTYGNAME, unsafe.Pointer(&name[0])) },
	} {
		//cover:ignore a pseudo-terminal call that cannot fail on a healthy machine
		if err := step(); err != nil {
			master.Close()
			return nil, nil, err
		}
	}
	slave, err = os.OpenFile(string(name[:bytes.IndexByte(name[:], 0)]), os.O_RDWR|unix.O_NOCTTY, 0)
	//cover:ignore a pseudo-terminal call that cannot fail on a healthy machine
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}
