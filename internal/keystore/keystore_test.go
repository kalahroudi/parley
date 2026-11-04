// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kalahroudi/parley/internal/fsperm"
)

type memKeyring struct {
	m      map[string]string
	getErr error
	setErr error
}

func (m *memKeyring) Get(s, u string) (string, error) {
	if m.getErr != nil {
		return "", m.getErr
	}
	v, ok := m.m[s+"/"+u]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (m *memKeyring) Set(s, u, v string) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.m[s+"/"+u] = v
	return nil
}

func TestKeychainStoreRoundTrip(t *testing.T) {
	m := &memKeyring{m: map[string]string{}}
	ks := &KeychainStore{Account: "dev-1", KR: m}
	if _, err := ks.Load(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("empty: %v", err)
	}
	key, created, err := LoadOrCreate(ks, rand.Reader)
	if err != nil || !created {
		t.Fatal(created, err)
	}
	again, created, err := LoadOrCreate(ks, rand.Reader)
	if err != nil || created || !key.Equal(again) {
		t.Fatal("second load must return the same key")
	}
	if err := ks.Save(key); err == nil {
		t.Error("Save must not overwrite an existing key")
	}
	if _, ok := m.m[KeychainService+"/dev-1"]; !ok {
		t.Error("key not filed under the service and device id")
	}
}

func TestKeychainFailuresAreOpaque(t *testing.T) {
	secret := errors.New("secret-detail-from-keychain")
	m := &memKeyring{m: map[string]string{}, getErr: secret}
	ks := &KeychainStore{Account: "d", KR: m}
	_, err := ks.Load()
	if err == nil || errors.Is(err, ErrNoKey) || strings.Contains(err.Error(), "secret-detail") {
		t.Errorf("unavailable keychain must fail closed without leaking detail: %v", err)
	}
	if _, _, err := LoadOrCreate(ks, rand.Reader); err == nil {
		t.Error("LoadOrCreate must not mint a key when the keychain is unavailable")
	}
	m.getErr, m.setErr = nil, secret
	err = ks.Save(make(ed25519.PrivateKey, ed25519.PrivateKeySize))
	if err == nil || strings.Contains(err.Error(), "secret-detail") {
		t.Errorf("set failure: %v", err)
	}
	if _, _, err := LoadOrCreate(ks, rand.Reader); err == nil {
		t.Error("a key that could not be stored must not be used")
	}
}

func TestCorruptKeyIsNeverReplaced(t *testing.T) {
	for _, bad := range []string{"", "zz", "00", strings.Repeat("0", 63), strings.Repeat("0", 62), strings.Repeat("0", 66)} {
		m := &memKeyring{m: map[string]string{KeychainService + "/d": bad}}
		ks := &KeychainStore{Account: "d", KR: m}
		if _, _, err := LoadOrCreate(ks, rand.Reader); !errors.Is(err, ErrKeyCorrupt) {
			t.Errorf("%q: want ErrKeyCorrupt, got %v", bad, err)
		}
		if m.m[KeychainService+"/d"] != bad {
			t.Errorf("%q: the stored value was replaced", bad)
		}
	}
	// A valid seed of exactly the right length is accepted.
	m := &memKeyring{m: map[string]string{KeychainService + "/d": strings.Repeat("ab", ed25519.SeedSize)}}
	if _, err := (&KeychainStore{Account: "d", KR: m}).Load(); err != nil {
		t.Errorf("valid seed: %v", err)
	}
}

type failRand struct{}

func (failRand) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

type memStore struct {
	k       ed25519.PrivateKey
	saveErr error
	loads   int
}

func (m *memStore) Load() (ed25519.PrivateKey, error) {
	m.loads++
	if m.k == nil {
		return nil, ErrNoKey
	}
	return m.k, nil
}

func (m *memStore) Save(k ed25519.PrivateKey) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.k = k
	return nil
}

func TestLoadOrCreateFailures(t *testing.T) {
	if _, _, err := LoadOrCreate(&memStore{}, failRand{}); err == nil {
		t.Error("entropy failure must be an error")
	}
	ks := &memStore{saveErr: errors.New("disk full")}
	if _, _, err := LoadOrCreate(ks, rand.Reader); err == nil {
		t.Error("save failure must be an error")
	}
	if ks.k != nil {
		t.Error("nothing may be stored when saving failed")
	}
}

func TestLoadOrCreateLocked(t *testing.T) {
	locks, released := 0, 0
	lock := func() (func(), error) { locks++; return func() { released++ }, nil }
	ks := &memStore{}
	key, created, err := LoadOrCreateLocked(ks, rand.Reader, lock)
	if err != nil || !created || key == nil || locks != 1 || released != 1 {
		t.Fatalf("create: created=%v err=%v locks=%d released=%d", created, err, locks, released)
	}
	// A stored key is returned without taking the lock.
	got, created, err := LoadOrCreateLocked(ks, rand.Reader, lock)
	if err != nil || created || !got.Equal(key) || locks != 1 {
		t.Errorf("existing key: created=%v err=%v locks=%d", created, err, locks)
	}
	// A store error other than ErrNoKey is returned, not retried under the lock.
	broken := &KeychainStore{Account: "d", KR: &memKeyring{m: map[string]string{}, getErr: errors.New("x")}}
	if _, _, err := LoadOrCreateLocked(broken, rand.Reader, lock); err == nil || errors.Is(err, ErrNoKey) || locks != 1 {
		t.Errorf("broken store: %v locks=%d", err, locks)
	}
}

func TestLoadOrCreateLockedWhenLockIsHeld(t *testing.T) {
	ks := &memStore{}
	held := errors.New("held")
	_, _, err := LoadOrCreateLocked(ks, rand.Reader, func() (func(), error) { return nil, held })
	if !errors.Is(err, held) || ks.k != nil {
		t.Errorf("a key was created without the lock: %v", err)
	}
	// A second process created the key between the first Load and the lock.
	racing := &raceStore{}
	key, created, err := LoadOrCreateLocked(racing, rand.Reader, func() (func(), error) { racing.k = racing.winner; return func() {}, nil })
	if err != nil || created || !key.Equal(racing.winner) {
		t.Errorf("the key created by the other process must be used: created=%v err=%v", created, err)
	}
}

// raceStore has no key until its lock is taken, as if another daemon created one meanwhile.
type raceStore struct {
	memStore
	winner ed25519.PrivateKey
}

func (r *raceStore) Load() (ed25519.PrivateKey, error) {
	if r.winner == nil {
		_, r.winner, _ = ed25519.GenerateKey(rand.Reader)
	}
	return r.memStore.Load()
}

func TestFileStore(t *testing.T) {
	dir := filepath.Join(tempDir(t), "cfg")
	fs := FileStore{Dir: dir}
	if _, err := fs.Load(); !errors.Is(err, ErrNoKey) {
		t.Fatal(err)
	}
	key, created, err := LoadOrCreate(fs, rand.Reader)
	if err != nil || !created {
		t.Fatal(err)
	}
	got, err := fs.Load()
	if err != nil || !got.Equal(key) {
		t.Fatalf("round trip: %v", err)
	}
	if err := fsperm.CheckFile(filepath.Join(dir, "device.key")); err != nil {
		t.Errorf("key file is not private: %v", err)
	}
	if err := fs.Save(key); err == nil {
		t.Error("Save must not overwrite")
	}
	os.WriteFile(filepath.Join(dir, "device.key"), []byte("junk"), 0o600)
	if _, err := fs.Load(); !errors.Is(err, ErrKeyCorrupt) {
		t.Errorf("corrupt: %v", err)
	}
}

func TestFileStoreErrors(t *testing.T) {
	dir := tempDir(t)
	// A directory where device.key should be: not a key file, and not "no key".
	os.Mkdir(filepath.Join(dir, "device.key"), 0o700)
	if _, err := (FileStore{Dir: dir}).Load(); err == nil || errors.Is(err, ErrNoKey) {
		t.Errorf("unreadable key file: %v", err)
	}
	// The directory is a file: it cannot be created.
	f := filepath.Join(tempDir(t), "f")
	os.WriteFile(f, nil, 0o600)
	if err := (FileStore{Dir: filepath.Join(f, "sub")}).Save(make(ed25519.PrivateKey, 64)); err == nil {
		t.Error("save under a file must fail")
	}
	// device.key already exists as a directory: the exclusive create fails.
	if err := (FileStore{Dir: dir}).Save(make(ed25519.PrivateKey, 64)); err == nil {
		t.Error("create over an existing entry must fail")
	}
}

func TestFileStoreReadFailure(t *testing.T) {
	fs := FileStore{Dir: filepath.Join(tempDir(t), "cfg")}
	if _, _, err := LoadOrCreate(fs, rand.Reader); err != nil {
		t.Fatal(err)
	}
	old := readFile
	readFile = func(string) ([]byte, error) { return nil, errors.New("io") }
	defer func() { readFile = old }()
	if _, err := fs.Load(); err == nil || errors.Is(err, ErrNoKey) || errors.Is(err, ErrKeyCorrupt) {
		t.Errorf("a read failure must not look like a missing or corrupt key: %v", err)
	}
}

type brokenFile struct {
	writeErr, syncErr, closeErr error
	closed                      bool
}

func (b *brokenFile) Write(p []byte) (int, error) { return len(p), b.writeErr }
func (b *brokenFile) Sync() error                 { return b.syncErr }
func (b *brokenFile) Close() error                { b.closed = true; return b.closeErr }

func TestFileStoreSaveFailuresLeaveNothingBehind(t *testing.T) {
	boom := errors.New("boom")
	for name, bf := range map[string]*brokenFile{
		"write": {writeErr: boom}, "sync": {syncErr: boom}, "close": {closeErr: boom},
	} {
		dir := filepath.Join(tempDir(t), "cfg")
		old := newFile
		newFile = func(path string) (keyFile, error) {
			os.WriteFile(path, []byte("partial"), 0o600) // what a real create leaves
			return bf, nil
		}
		err := FileStore{Dir: dir}.Save(make(ed25519.PrivateKey, ed25519.PrivateKeySize))
		newFile = old
		if !errors.Is(err, boom) || !bf.closed {
			t.Errorf("%s: err=%v closed=%v", name, err, bf.closed)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "device.key")); name != "close" && statErr == nil {
			t.Errorf("%s: a partial key file was left behind", name)
		}
	}
}

func TestZeroAndDecodeSeed(t *testing.T) {
	b := []byte{1, 2, 3}
	Zero(b)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Error("not zeroed")
	}
}

func tempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ks")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
