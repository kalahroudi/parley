// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/keystore"
)

// syncBuf is a log sink the test can read while the daemon writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

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

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type failRand struct{}

func (failRand) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// failSave is a key store with no key whose Save fails.
type failSave struct{}

func (failSave) Load() (ed25519.PrivateKey, error) { return nil, keystore.ErrNoKey }
func (failSave) Save(ed25519.PrivateKey) error     { return errors.New("disk full") }
