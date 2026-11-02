// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// ErrStore means the persisted rollback state could not be read or written.
// The Tracker fails closed: it accepts nothing it could not durably record.
var ErrStore = errors.New("binding: rollback store unavailable or corrupt")

// Record is the highest binding seen for one device.
type Record struct {
	Tenant   string `json:"tenant"`
	DeviceID string `json:"device_id"`
	Version  uint64 `json:"version"`
	Encoded  []byte `json:"encoded"` // Binding.Encode of that version
}

// Store persists the Tracker's highest-seen bindings. Save receives the full
// state and must be durable before it returns nil.
type Store interface {
	// Load returns the saved records; a store that was never written returns none.
	Load() ([]Record, error)
	Save([]Record) error
}

// Locker is implemented by stores that several processes may share. Lock
// returns once this process holds the store exclusively and the release func
// frees it. The Tracker holds it across its read-modify-write so two daemons
// sharing a store cannot overwrite each other's records.
type Locker interface {
	Lock() (release func() error, err error)
}

const (
	storeFormat = 1
	lockTimeout = 10 * time.Second
	lockPoll    = 10 * time.Millisecond
)

type storeFile struct {
	Format  int      `json:"format"`
	Records []Record `json:"records"`
}

// FileStore is a Store backed by one JSON file, replaced atomically (temp file,
// fsync, rename) so a failed write never leaves a truncated file behind.
type FileStore struct {
	path string
	// Seams for tests: each stands in for an OS call that cannot fail on demand.
	rename  func(oldpath, newpath string) error
	marshal func(any) ([]byte, error)
	create  func(dir, pattern string) (tempFile, error)
	syncDir func(dir string) error
	try     func(*os.File) (bool, error)

	lockTimeout time.Duration
}

// tempFile is the part of *os.File that Save uses.
type tempFile interface {
	Name() string
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

func createTemp(dir, pattern string) (tempFile, error) { return os.CreateTemp(dir, pattern) } // created 0600

// NewFileStore returns a store at path. The parent directory must exist.
func NewFileStore(path string) *FileStore {
	return &FileStore{
		path: path, rename: os.Rename, marshal: json.Marshal, create: createTemp, syncDir: syncDir,
		try: tryLock, lockTimeout: lockTimeout,
	}
}

// Lock takes an exclusive OS lock (flock, LockFileEx) on a sidecar file next to
// the store; the store file itself is replaced by rename, so it cannot carry
// the lock. The OS drops the lock if the holder dies, so it is never stale.
// It fails with ErrStore if the lock is not obtained within the timeout.
func (f *FileStore) Lock() (func() error, error) {
	lf, err := os.OpenFile(f.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStore, err)
	}
	deadline := time.Now().Add(f.lockTimeout)
	for {
		ok, err := f.try(lf)
		if err != nil {
			lf.Close()
			return nil, fmt.Errorf("%w: lock: %v", ErrStore, err)
		}
		if ok {
			return func() error { return errors.Join(unlock(lf), lf.Close()) }, nil
		}
		if !time.Now().Before(deadline) {
			lf.Close()
			return nil, fmt.Errorf("%w: timed out waiting for the store lock", ErrStore)
		}
		time.Sleep(lockPoll)
	}
}

func (f *FileStore) Load() ([]Record, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStore, err)
	}
	var sf storeFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sf); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStore, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrStore)
	}
	if sf.Format != storeFormat {
		return nil, fmt.Errorf("%w: unsupported format %d", ErrStore, sf.Format)
	}
	seen := map[deviceKey]bool{}
	for _, r := range sf.Records {
		k := deviceKey{r.Tenant, r.DeviceID}
		if r.Tenant == "" || r.DeviceID == "" || r.Version == 0 || len(r.Encoded) == 0 || seen[k] {
			return nil, fmt.Errorf("%w: bad record", ErrStore)
		}
		seen[k] = true
	}
	return sf.Records, nil
}

func (f *FileStore) Save(recs []Record) (err error) {
	recs = append([]Record(nil), recs...)
	slices.SortFunc(recs, func(a, b Record) int {
		if c := cmp.Compare(a.Tenant, b.Tenant); c != 0 {
			return c
		}
		return cmp.Compare(a.DeviceID, b.DeviceID)
	})
	data, err := f.marshal(storeFile{Format: storeFormat, Records: recs})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStore, err)
	}
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
	// Make the rename itself durable.
	return f.syncDir(dir)
}
