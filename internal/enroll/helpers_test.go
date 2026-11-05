// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/keystore"
	"github.com/kalahroudi/parley/internal/root"
)

const podToken = "pet_" + "0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeGateway implements the routes enrollment and login use, with the
// semantics that matter here: a request with a device-chosen id is idempotent,
// a pod token is spent by the first request that uses it, and the binding is
// signed by a real root key so the daemon's verification is the real one.
type fakeGateway struct {
	t       *testing.T
	srv     *httptest.Server
	rootPub ed25519.PublicKey
	rootKey ed25519.PrivateKey

	mu       sync.Mutex
	posts    int // enroll/request calls received
	reqs     map[string]*fakeReq
	spent    bool
	polls    int
	pending  int                                   // answer "pending" this many times before approving
	status   func(id string) (int, map[string]any) // overrides the status answer
	reqReply func(id, poll string) (int, any)      // overrides the request answer
	rootBody func() any
	bind     func(id string, key []byte) *binding.Signed
	bound    map[string]*binding.Signed
	login    fakeLogin
}

type fakeReq struct {
	key         []byte
	poll, name  string
	auth, token string
}

type fakeLogin struct {
	starts, polls int
	sessionHash   string
	pollHash      string
	doneAfter     int
	notFound      bool
	startBody     func() (int, any)
}

func newFakeGateway(t *testing.T) *fakeGateway {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGateway{t: t, rootPub: pub, rootKey: priv, reqs: map[string]*fakeReq{}, bound: map[string]*binding.Signed{}}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

// set changes the gateway's behaviour while its server goroutines may be reading it; the snapshots below read the same way.
func (g *fakeGateway) set(f func(g *fakeGateway)) { g.mu.Lock(); defer g.mu.Unlock(); f(g) }

func (g *fakeGateway) snapshot() map[string]*fakeReq {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]*fakeReq, len(g.reqs))
	for k, v := range g.reqs {
		c := *v
		out[k] = &c
	}
	return out
}
func (g *fakeGateway) pollCount() int       { g.mu.Lock(); defer g.mu.Unlock(); return g.polls }
func (g *fakeGateway) loginSnap() fakeLogin { g.mu.Lock(); defer g.mu.Unlock(); return g.login }

func (g *fakeGateway) distinct() int { g.mu.Lock(); defer g.mu.Unlock(); return len(g.reqs) }
func (g *fakeGateway) rawPosts() int { g.mu.Lock(); defer g.mu.Unlock(); return g.posts }

func (g *fakeGateway) signed(id string, key []byte, version uint64) *binding.Signed {
	b, err := binding.Sign(g.rootKey, binding.Binding{Tenant: "acme", Owner: "alice@acme.test", DeviceID: id, SigningKey: key, Version: version, NotAfter: time.Now().Add(binding.Lifetime)})
	if err != nil {
		g.t.Fatal(err)
	}
	return b
}

func (g *fakeGateway) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var b map[string]any
	_ = json.NewDecoder(r.Body).Decode(&b)
	reply := func(code int, v any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	str := func(k string) string { s, _ := b[k].(string); return s }
	switch r.URL.Path {
	case "/v1/root":
		if g.rootBody != nil {
			reply(200, g.rootBody())
			return
		}
		reply(200, map[string]any{"root_public_key": []byte(g.rootPub)})
	case "/v1/enroll/request":
		g.posts++
		key, _ := base64Bytes(b["signing_key"])
		id, poll := str("id"), str("poll")
		if prior, ok := g.reqs[id]; ok {
			if prior.poll == poll && string(prior.key) == string(key) {
				reply(202, map[string]any{"id": id, "poll": poll})
			} else {
				reply(409, nil)
			}
			return
		}
		auth, token := r.Header.Get("Authorization"), str("token")
		switch {
		case token != "":
			if token != podToken || g.spent || str("tenant") != "acme" {
				reply(401, nil)
				return
			}
			g.spent = true
		case !strings.HasPrefix(auth, "Bearer ps_acme."):
			reply(401, nil)
			return
		}
		if g.reqReply != nil {
			if code, v := g.reqReply(id, poll); code != 202 {
				reply(code, v)
				return
			}
		}
		g.reqs[id] = &fakeReq{key: key, poll: poll, name: str("name"), auth: auth, token: token}
		reply(202, map[string]any{"id": id, "poll": poll})
	case "/v1/enroll/status":
		rq, ok := g.reqs[str("id")]
		if !ok || rq.poll != str("poll") || str("tenant") != "acme" {
			reply(404, nil)
			return
		}
		if g.status != nil {
			code, st := g.status(str("id"))
			reply(code, st)
			return
		}
		g.polls++
		if g.pending > 0 {
			g.pending--
			reply(200, map[string]any{"status": "pending"})
			return
		}
		// The gateway stores the binding the admin posted and returns that same one on every poll.
		bd := g.bound[str("id")]
		if bd == nil {
			bd = g.signed(str("id"), rq.key, 1)
			if g.bind != nil {
				bd = g.bind(str("id"), rq.key)
			}
			g.bound[str("id")] = bd
		}
		reply(200, map[string]any{"status": "approved", "binding": bd})
	case "/v1/login/start":
		g.login.starts++
		g.login.sessionHash, g.login.pollHash = str("session_hash"), str("poll_hash")
		if g.login.startBody != nil {
			code, v := g.login.startBody()
			reply(code, v)
			return
		}
		reply(201, map[string]any{"id": strings.Repeat("a", 32), "code": "ABCD-1234", "expires_at": time.Now().Add(time.Minute).UnixMilli()})
	case "/v1/login/poll":
		g.login.polls++
		if g.login.notFound || str("id") != strings.Repeat("a", 32) || hexSHA(str("poll")) != g.login.pollHash {
			reply(404, nil)
			return
		}
		if g.login.polls > g.login.doneAfter {
			reply(200, map[string]any{"state": "done"})
			return
		}
		reply(200, map[string]any{"state": "pending"})
	default:
		reply(404, nil)
	}
}

func base64Bytes(v any) ([]byte, error) {
	s, _ := v.(string)
	var out []byte
	err := json.Unmarshal([]byte(`"`+s+`"`), &out)
	return out, err
}

// memKeys is a key store in memory that returns copies, as a real store does (the caller zeroes its own).
type memKeys struct {
	mu      sync.Mutex
	key     ed25519.PrivateKey
	saves   int
	loadErr error
}

func (m *memKeys) Load() (ed25519.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	if m.key == nil {
		return nil, keystore.ErrNoKey
	}
	return append(ed25519.PrivateKey(nil), m.key...), nil
}

func (m *memKeys) Save(k ed25519.PrivateKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saves++
	m.key = append(ed25519.PrivateKey(nil), k...)
	return nil
}

func (m *memKeys) forget() { m.mu.Lock(); m.key = nil; m.mu.Unlock() }

type failSave struct{}

func (failSave) Load() (ed25519.PrivateKey, error) { return nil, keystore.ErrNoKey }
func (failSave) Save(ed25519.PrivateKey) error     { return errors.New("disk full") }

type failRand struct{}

func (failRand) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// memSessions is a SessionStore in memory.
type memSessions struct {
	mu         sync.Mutex
	token      map[string]string
	saveErr    error
	loadErr    error
	clearErr   error
	clears     int
	savedCount int
}

func (m *memSessions) Save(tenant, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	if m.token == nil {
		m.token = map[string]string{}
	}
	m.token[tenant] = token
	m.savedCount++
	return nil
}

func (m *memSessions) Load(tenant string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return "", m.loadErr
	}
	if t, ok := m.token[tenant]; ok {
		return t, nil
	}
	return "", ErrNoSession
}

func (m *memSessions) Clear(tenant string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clears++
	if m.clearErr != nil {
		return m.clearErr
	}
	delete(m.token, tenant)
	return nil
}

func (m *memSessions) has(tenant string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.token[tenant]
	return ok
}

type env struct {
	t    *testing.T
	gw   *fakeGateway
	dirs daemon.Dirs
	keys *memKeys
	sess *memSessions
	opts Options
	mu   sync.Mutex
	log  []string
}

func newEnv(t *testing.T) *env {
	e := &env{t: t, gw: newFakeGateway(t), keys: &memKeys{}, sess: &memSessions{}}
	dir := t.TempDir()
	e.dirs = daemon.Dirs{Config: filepath.Join(dir, "cfg"), State: filepath.Join(dir, "state")}
	e.sess.token = map[string]string{"acme": "ps_acme." + strings.Repeat("a", 64)}
	e.opts = Options{
		Dirs: e.dirs, Gateway: e.gw.srv.URL, Tenant: "acme", RootFingerprint: root.Fingerprint(e.gw.rootPub), Name: "laptop",
		Sessions: e.sess, KeyStore: daemon.KeyStoreFile, Keys: e.keys, Poll: time.Millisecond,
		Progress: func(s string) { e.mu.Lock(); e.log = append(e.log, s); e.mu.Unlock() },
	}
	return e
}

func (e *env) resume() Options {
	return Options{Dirs: e.dirs, Sessions: e.sess, Keys: e.keys, Poll: time.Millisecond, Progress: e.opts.Progress}
}
func (e *env) path(name string) string { return filepath.Join(e.dirs.State, name) }
func (e *env) have(p string) bool      { _, err := os.Stat(p); return err == nil }
func (e *env) text() string            { e.mu.Lock(); defer e.mu.Unlock(); return strings.Join(e.log, "\n") }
func (e *env) phase() string {
	s, err := loadState(e.dirs.State)
	if err != nil {
		return "none:" + err.Error()
	}
	return s.Phase
}

func fingerprintHex(pub []byte) string { h := sha256.Sum256(pub); return hex.EncodeToString(h[:]) }
