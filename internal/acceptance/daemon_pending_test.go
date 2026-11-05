// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/connect"
	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/supervisor"
)

// T410 builds the daemon core. What it deliberately leaves to later tasks is
// named here, so it cannot be forgotten: each test skips while its task is open
// and fails once tasks.md ticks the task.

// A daemon with a recorded binding and no other configuration earns a connect token by signing the gateway's
// challenge with its device key (verified by the gateway below against the key in the binding, over the exact
// message internal/connect defines), opens the tunnel with it, and holds it open. Each reconnect earns a fresh,
// single-use token. (The real Worker is driven the same way by tests/pending-t310.test.mjs.)
func TestDaemonGetsConnectTokenAndConnects(t *testing.T) {
	rootPub, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	devPub, devKey, _ := ed25519.GenerateKey(rand.Reader)
	var mu sync.Mutex
	var issued, opened []string
	spent := map[string]bool{}
	drop := make(chan struct{})
	const expires = int64(4102444800000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/connect/challenge":
			json.NewEncoder(w).Encode(map[string]any{"challenge": fmt.Sprint("ch", time.Now().UnixNano()), "expires_at": expires})
		case "/v1/connect/token":
			var in struct {
				Tenant, Device, Challenge string
				Version                   uint64
				Scope                     connect.Scope
				Signature                 []byte
			}
			json.NewDecoder(r.Body).Decode(&in)
			if in.Version != 7 || in.Scope != connect.ScopeConnect || !ed25519.Verify(devPub, connect.Message(in.Tenant, in.Device, in.Challenge, expires, in.Version, in.Scope), in.Signature) {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			mu.Lock()
			tok := fmt.Sprint("pdt_t1.dev-1.", len(issued)+1)
			issued = append(issued, tok)
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"token": tok, "expires_at": time.Now().Add(5 * time.Minute).UnixMilli()})
		case "/v1/connect":
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			mu.Lock()
			opened = append(opened, tok)
			ok := slices.Contains(issued, tok) && !spent[tok]
			spent[tok] = true // single use
			mu.Unlock()
			if !ok {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.CloseNow()
			if _, _, err := c.Read(r.Context()); err != nil {
				return
			}
			c.Write(r.Context(), websocket.MessageText, []byte(`{"t":"welcome","session":"s","resumed":false,"rx_seq":0,"heartbeat_ms":1000}`))
			select {
			case <-drop:
			case <-r.Context().Done():
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := os.TempDir()
	if runtime.GOOS != "windows" {
		dir = "/tmp" // a unix socket path must stay short
	}
	dir, err := os.MkdirTemp(dir, "pd")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	dir = filepath.Join(dir, "p")
	cfg := daemon.Config{Format: 1, Tenant: "t1", DeviceID: "dev-1", GatewayURL: srv.URL, RootPublicKey: rootPub, KeyStore: daemon.KeyStoreFile}
	raw, _ := json.Marshal(cfg)
	if _, err := daemon.ParseConfig(raw); err != nil {
		t.Fatal(err)
	}
	d, err := daemon.New(cfg, daemon.Dirs{Config: dir, State: dir}, daemon.Deps{
		Log: logx.New(io.Discard), Harden: func() error { return nil }, Keys: memKeys{devKey}, MinBackoff: time.Millisecond, ShutdownTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := binding.Sign(rootKey, binding.Binding{Tenant: "t1", Owner: "o", DeviceID: "dev-1", SigningKey: devPub, Version: 7, NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Trust().Tracker.Accept(signed, time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	defer func() { cancel(); <-done }()

	snap := func() ([]string, []string) {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(issued), slices.Clone(opened)
	}
	wait := func(what string, cond func() bool) {
		for i := 0; i < 1000; i++ {
			if cond() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}
	wait("the first tunnel connection", func() bool { _, o := snap(); return len(o) == 1 })
	if i, o := snap(); len(i) != 1 || o[0] != i[0] {
		t.Fatalf("issued %v, opened %v: the tunnel did not present the token it earned", i, o)
	}
	wait("the tunnel to run", func() bool {
		r, err := localsock.Call(context.Background(), daemon.Dirs{Config: dir, State: dir}.SocketPath(), "status", nil)
		if err != nil || !r.OK {
			return false
		}
		var st daemon.StatusInfo
		json.Unmarshal(r.Result, &st)
		for _, c := range st.Components {
			if c.Name == "tunnel" && c.State == supervisor.StateRunning {
				return true
			}
		}
		return false
	})
	drop <- struct{}{}
	wait("a reconnect", func() bool { _, o := snap(); return len(o) >= 2 })
	if i, o := snap(); len(i) < 2 || i[0] == i[1] || o[1] != i[1] {
		t.Fatalf("the reconnect reused or invented a token: issued %v, opened %v", i, o)
	}
}

// memKeys is a key store that already holds the device key.
type memKeys struct{ k ed25519.PrivateKey }

func (m memKeys) Load() (ed25519.PrivateKey, error) {
	return append(ed25519.PrivateKey(nil), m.k...), nil
}
func (m memKeys) Save(ed25519.PrivateKey) error { return errors.New("not expected") }

func TestPending_DaemonEnrollmentAndBindings(t *testing.T) {
	pending(t, "T411", "the daemon core opens the binding tracker but has no enrollment flow; assert a fresh daemon enrolls, receives its root-signed binding and records it before serving")
}

func TestPending_WindowsDaemonPeerRestriction(t *testing.T) {
	pending(t, "T505", "on Windows the control socket is AF_UNIX in a protected-DACL directory with no peer-credential check (see internal/localsock). Assert the Windows daemon uses a named pipe with a current-user-only ACL, or an equivalent peer check, and that a process of another local user cannot connect, while the same user can; also that the DACL check refuses a pipe or directory open to Everyone, Users or Authenticated Users")
}
