// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

type memKeyring struct {
	m      map[string]string
	getErr error
	setErr error
}

func (m *memKeyring) kr() kring {
	return kring{
		get: func(s, u string) (string, error) {
			if m.getErr != nil {
				return "", m.getErr
			}
			v, ok := m.m[s+"/"+u]
			if !ok {
				return "", keyring.ErrNotFound
			}
			return v, nil
		},
		set: func(s, u, v string) error {
			if m.setErr != nil {
				return m.setErr
			}
			m.m[s+"/"+u] = v
			return nil
		},
	}
}

func TestKeychainStoreRoundTrip(t *testing.T) {
	m := &memKeyring{m: map[string]string{}}
	ks := &KeychainStore{Account: "dev-1", kr: m.kr()}
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
	ks := &KeychainStore{Account: "d", kr: m.kr()}
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
	for _, bad := range []string{"", "zz", "00", strings.Repeat("0", 63)} {
		m := &memKeyring{m: map[string]string{KeychainService + "/d": bad}}
		ks := &KeychainStore{Account: "d", kr: m.kr()}
		if _, _, err := LoadOrCreate(ks, rand.Reader); !errors.Is(err, ErrKeyCorrupt) {
			t.Errorf("%q: want ErrKeyCorrupt, got %v", bad, err)
		}
		if m.m[KeychainService+"/d"] != bad {
			t.Errorf("%q: the stored value was replaced", bad)
		}
	}
}

type failRand struct{}

func (failRand) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

type failSave struct{ memStore }

func (failSave) Save(ed25519.PrivateKey) error { return errors.New("disk full") }

type memStore struct{ k ed25519.PrivateKey }

func (m *memStore) Load() (ed25519.PrivateKey, error) {
	if m.k == nil {
		return nil, ErrNoKey
	}
	return m.k, nil
}
func (m *memStore) Save(k ed25519.PrivateKey) error { m.k = k; return nil }

func TestLoadOrCreateFailures(t *testing.T) {
	if _, _, err := LoadOrCreate(&memStore{}, failRand{}); err == nil {
		t.Error("entropy failure must be an error")
	}
	if _, _, err := LoadOrCreate(&failSave{}, rand.Reader); err == nil {
		t.Error("save failure must be an error")
	}
}

func TestFileKeyStore(t *testing.T) {
	dir := filepath.Join(shortTemp(t), "cfg")
	fs := FileKeyStore{Dir: dir}
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
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, "device.key"))
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("key file mode %o", fi.Mode().Perm())
		}
	}
	if err := fs.Save(key); err == nil {
		t.Error("Save must not overwrite")
	}
	os.WriteFile(filepath.Join(dir, "device.key"), []byte("junk"), 0o600)
	if _, err := fs.Load(); !errors.Is(err, ErrKeyCorrupt) {
		t.Errorf("corrupt: %v", err)
	}
}

func TestFileKeyStoreErrors(t *testing.T) {
	dir := shortTemp(t)
	// A directory where device.key should be: read fails, but not as "no key".
	os.Mkdir(filepath.Join(dir, "device.key"), 0o700)
	if _, err := (FileKeyStore{Dir: dir}).Load(); err == nil || errors.Is(err, ErrNoKey) {
		t.Errorf("unreadable key file: %v", err)
	}
	// The directory is a file: it cannot be created.
	f := filepath.Join(shortTemp(t), "f")
	os.WriteFile(f, nil, 0o600)
	if err := (FileKeyStore{Dir: filepath.Join(f, "sub")}).Save(make(ed25519.PrivateKey, 64)); err == nil {
		t.Error("save under a file must fail")
	}
	// device.key already exists as a directory: O_EXCL create fails.
	if err := (FileKeyStore{Dir: dir}).Save(make(ed25519.PrivateKey, 64)); err == nil {
		t.Error("create over an existing entry must fail")
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3}
	zero(b)
	if b[0]|b[1]|b[2] != 0 {
		t.Error("not zeroed")
	}
}

// shortTemp returns a short private temp directory: unix socket paths are
// limited to about 104 bytes and t.TempDir paths on macOS are too long.
func shortTemp(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "pd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
