// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/logx"
)

// noCloseListener hides Close so a test can make Accept return a connection
// after the server's shutdown sweep has already run.
type noCloseListener struct{ net.Listener }

func (noCloseListener) Close() error { return nil }

func TestConnectionAcceptedAfterShutdownIsClosed(t *testing.T) {
	ln, err := listenSocket(filepath.Join(shortTemp(t), "s", "d.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // shutdown has begun, and its sweep of open connections is over
	s := &server{log: logx.New(&syncBuf{}), uid: os.Geteuid()}
	done := make(chan struct{})
	go func() { s.serve(ctx, noCloseListener{ln}); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return: a connection accepted during shutdown was left open")
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("the connection accepted during shutdown was not closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("the connection accepted during shutdown was left open")
	}
}

func TestListenSocketRefusesRelativePath(t *testing.T) {
	for _, p := range []string{"@abstract", "@abstract/parleyd.sock", "rel/parleyd.sock"} {
		if _, err := listenSocket(p); err == nil {
			t.Errorf("listenSocket(%q) accepted a non-absolute path", p)
		}
	}
}

func TestDefaultDirsAreAbsolute(t *testing.T) {
	d, err := DefaultDirs(func(string) string { return "@home" }, nil)
	if err != nil || !filepath.IsAbs(d.Config) || !filepath.IsAbs(d.State) || !filepath.IsAbs(d.SocketPath()) {
		t.Errorf("PARLEY_HOME=@home gave %+v, %v", d, err)
	}
}

func TestRefreshIntervalHasAnUpperBound(t *testing.T) {
	if _, err := ParseConfig([]byte(goodJSON(`,"refresh_interval":"25h"`))); !errors.Is(err, ErrConfig) {
		t.Errorf("a refresh interval longer than 24h must be refused: %v", err)
	}
	if _, err := ParseConfig([]byte(goodJSON(`,"refresh_interval":"24h"`))); err != nil {
		t.Errorf("24h is allowed: %v", err)
	}
}

// emptyStore reports no key and records what is saved.
type emptyStore struct {
	loads int
	saved ed25519.PrivateKey
}

func (e *emptyStore) Load() (ed25519.PrivateKey, error) {
	e.loads++
	if e.saved != nil {
		return e.saved, nil
	}
	return nil, ErrNoKey
}
func (e *emptyStore) Save(k ed25519.PrivateKey) error { e.saved = k; return nil }

func TestFirstRunKeyCreationNeedsTheInstanceLock(t *testing.T) {
	dir := shortTemp(t)
	// Another daemon holds the lock (it is starting, or running): this one must
	// not mint a key the keychain would then overwrite.
	release, err := lockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	ks := &emptyStore{}
	if _, _, err := loadOrCreateOnce(ks, rand.Reader, dir); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("creation under a held lock: %v", err)
	}
	if ks.saved != nil {
		t.Error("a key was created without the lock")
	}
	release()
	key, created, err := loadOrCreateOnce(ks, rand.Reader, dir)
	if err != nil || !created || key == nil {
		t.Fatalf("creation with the lock free: %v", err)
	}
	// With a key present there is no lock at all, so a running daemon does not block New.
	release, err = lockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	got, created, err := loadOrCreateOnce(ks, rand.Reader, dir)
	if err != nil || created || !got.Equal(key) {
		t.Errorf("existing key: created=%v err=%v", created, err)
	}
}
