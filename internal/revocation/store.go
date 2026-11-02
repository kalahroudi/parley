// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package revocation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// ErrStore means the saved list could not be read or written.
var ErrStore = errors.New("revocation: store unavailable or corrupt")

// FileStore is a Store backed by one JSON file, replaced atomically (temp file,
// fsync, rename) so a failed write never leaves a truncated file behind.
type FileStore struct {
	path string
	// Replaceable in tests, to reach the failure paths of a real disk.
	create  func(dir, pattern string) (tmpFile, error)
	rename  func(oldpath, newpath string) error
	syncDir func(dir string) error
}

type tmpFile interface {
	io.Writer
	Name() string
	Sync() error
	Close() error
}

func createTemp(dir, pattern string) (tmpFile, error) { return os.CreateTemp(dir, pattern) } // 0600

var goos = runtime.GOOS // replaceable in tests

func syncDir(dir string) error {
	if goos == "windows" { // Windows cannot open or sync directories.
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// NewFileStore returns a store at path. The parent directory must exist.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path, create: createTemp, rename: os.Rename, syncDir: syncDir}
}

func (f *FileStore) Load() (*Signed, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStore, err)
	}
	var s Signed
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStore, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrStore)
	}
	return &s, nil
}

func (f *FileStore) Save(s *Signed) (err error) {
	data, _ := json.Marshal(s) // Signed holds only strings, numbers, times and bytes: cannot fail.
	dir := filepath.Dir(f.path)
	tmp, err := f.create(dir, filepath.Base(f.path)+".tmp*")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStore, err)
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			err = fmt.Errorf("%w: %v", ErrStore, err)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = f.rename(tmp.Name(), f.path); err != nil {
		return err
	}
	return f.syncDir(dir)
}
