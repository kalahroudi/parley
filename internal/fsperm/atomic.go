// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package fsperm

import (
	"os"
	"path/filepath"
)

// tempFile is the part of *os.File that WriteAtomic uses.
type tempFile interface {
	Name() string
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// atomicOps are the OS calls WriteAtomic makes; tests replace them to fail each one.
type atomicOps struct {
	create  func(dir, pattern string) (tempFile, error)
	rename  func(oldpath, newpath string) error
	syncDir func(dir string) error
}

var osAtomic = atomicOps{
	create:  func(dir, pattern string) (tempFile, error) { return os.CreateTemp(dir, pattern) }, // created 0600
	rename:  os.Rename,
	syncDir: syncDir,
}

// WriteAtomic replaces the file at path with data so that a crash leaves the old
// file or the new one, never a partial one: the data goes to a private (0600)
// temp file in the same directory, is flushed to disk, renamed over path, and
// the rename is then made durable (where the OS allows syncing a directory;
// Windows does not, and its rename is already write-through). The directory
// must exist and be private (see EnsureDir).
func WriteAtomic(path string, data []byte) error { return writeAtomic(path, data, osAtomic) }

func writeAtomic(path string, data []byte, o atomicOps) error {
	dir := filepath.Dir(path)
	f, err := o.create(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = o.rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
		return err
	}
	return o.syncDir(dir)
}
