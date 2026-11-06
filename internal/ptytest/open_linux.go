// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package ptytest

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func open() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	//cover:ignore a pseudo-terminal call that cannot fail on a healthy machine
	if err != nil {
		return nil, nil, err
	}
	fd := int(master.Fd())
	//cover:ignore a pseudo-terminal call that cannot fail on a healthy machine
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	//cover:ignore a pseudo-terminal call that cannot fail on a healthy machine
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	//cover:ignore a pseudo-terminal call that cannot fail on a healthy machine
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}
