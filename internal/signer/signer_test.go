// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/revocation"
	"github.com/kalahroudi/parley/internal/root"
)

var fixedNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

type harness struct {
	t   *testing.T
	s   *Server
	url string
	dir string
	// seen holds every response body by request path, for the secrecy test.
	seen map[string][][]byte
}

func start(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	secret := NewSecret()
	s := &Server{Store: root.FileStore{Dir: dir}, BackupPath: filepath.Join(dir, "sub", "root-backup.json"), Secret: secret, Clock: func() time.Time { return fixedNow }}
	l, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s.Handler()}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return &harness{t, s, "http://" + l.Addr().String(), dir, map[string][][]byte{}}
}

// call sends an authenticated request and returns the status and raw body.
func (h *harness) call(method, path string, body any) (int, []byte) {
	h.t.Helper()
	var rd bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = *bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.url+path, &rd)
	req.Header.Set("Authorization", "Bearer "+h.s.Secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	h.seen[path] = append(h.seen[path], buf.Bytes())
	return resp.StatusCode, buf.Bytes()
}

func (h *harness) init() initResp {
	h.t.Helper()
	code, b := h.call("POST", "/v1/root/init", nil)
	if code != 200 {
		h.t.Fatalf("init: %d %s", code, b)
	}
	var r initResp
	json.Unmarshal(b, &r)
	return r
}

func TestEndpointBinding(t *testing.T) {
	s := &Server{Store: root.FileStore{Dir: t.TempDir()}}
	for _, addr := range []string{"0.0.0.0:0", "192.0.2.1:0", "example.com:0", ":0"} {
		if _, err := s.Listen(addr); !errors.Is(err, ErrNotLoopback) {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if _, err := s.Listen("nonsense"); err == nil {
		t.Error("bad address accepted")
	}
	l, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if _, err := s.Listen(l.Addr().String() + "x"); err == nil {
		t.Error("bad port accepted")
	}
	// A taken port is a plain error.
	l2, _ := s.Listen("127.0.0.1:0")
	defer l2.Close()
	if _, err := s.Listen(l2.Addr().String()); err == nil {
		t.Error("taken port accepted")
	}
}

func TestAdmission(t *testing.T) {
	h := start(t)
	good := func() *http.Request {
		r := httptest.NewRequest("GET", "/v1/root", nil)
		r.Host = h.s.host
		r.RemoteAddr = "127.0.0.1:5000"
		r.Header.Set("Authorization", "Bearer "+h.s.Secret)
		return r
	}
	cases := map[string]func(*http.Request){
		"no secret":    func(r *http.Request) { r.Header.Del("Authorization") },
		"wrong secret": func(r *http.Request) { r.Header.Set("Authorization", "Bearer nope") },
		"bare secret":  func(r *http.Request) { r.Header.Set("Authorization", h.s.Secret) },
		"non-loopback": func(r *http.Request) { r.RemoteAddr = "203.0.113.9:5000" },
		"garbage peer": func(r *http.Request) { r.RemoteAddr = "garbage" },
		"rebound host": func(r *http.Request) { r.Host = "evil.example:80" },
		"browser":      func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"null origin":  func(r *http.Request) { r.Header.Set("Origin", "null") },
	}
	if rec := httptest.NewRecorder(); func() int { h.s.Handler().ServeHTTP(rec, good()); return rec.Code }() != 200 {
		t.Fatalf("good request refused: %d", rec.Code)
	}
	for name, mutate := range cases {
		r := good()
		mutate(r)
		rec := httptest.NewRecorder()
		h.s.Handler().ServeHTTP(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	// IPv6 loopback and v4-mapped peers are loopback too.
	for _, peer := range []string{"[::1]:5000", "[::ffff:127.0.0.1]:5000"} {
		r := good()
		r.RemoteAddr = peer
		rec := httptest.NewRecorder()
		h.s.Handler().ServeHTTP(rec, r)
		if rec.Code != 200 {
			t.Errorf("%s: %d", peer, rec.Code)
		}
	}
	// Unpinned handler (never listened) and empty secret refuse everything.
	for _, s := range []*Server{{Secret: "x"}, {}} {
		s.Store = h.s.Store
		if s.Secret == "" {
			s.host = h.s.host
		}
		r := good()
		r.Header.Set("Authorization", "Bearer "+s.Secret)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Errorf("misconfigured server: %d", rec.Code)
		}
	}
	// Oversize bodies are cut off.
	code, _ := h.call("POST", "/v1/root/recover", map[string]string{"recovery_code": strings.Repeat("a", maxBody)})
	if code != http.StatusBadRequest {
		t.Errorf("oversize: %d", code)
	}
}

func TestRootInitAndStatus(t *testing.T) {
	h := start(t)
	var st statusResp
	code, b := h.call("GET", "/v1/root", nil)
	json.Unmarshal(b, &st)
	if code != 200 || st.Exists {
		t.Fatalf("fresh status: %d %s", code, b)
	}
	// Signing before init is a clear conflict.
	for _, p := range []string{"/v1/bindings/sign", "/v1/revocations/sign"} {
		if code, _ := h.call("POST", p, map[string]any{}); code != http.StatusConflict {
			t.Errorf("%s without root: %d", p, code)
		}
	}
	r := h.init()
	if r.Fingerprint == "" || r.RecoveryCode == "" {
		t.Fatalf("init reply: %+v", r)
	}
	if fi, err := os.Stat(h.s.BackupPath); err != nil || fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("backup: %v", err)
	}
	code, b = h.call("GET", "/v1/root", nil)
	json.Unmarshal(b, &st)
	if code != 200 || !st.Exists || st.Fingerprint != r.Fingerprint {
		t.Fatalf("status: %d %s", code, b)
	}
	// A second init changes nothing and mints no second recovery code.
	code, b = h.call("POST", "/v1/root/init", nil)
	if code != http.StatusConflict || strings.Contains(string(b), "recovery_code") {
		t.Fatalf("second init: %d %s", code, b)
	}
	k, _ := root.FileStore{Dir: h.dir}.Load()
	if root.Fingerprint(k.Public().(ed25519.PublicKey)) != r.Fingerprint {
		t.Fatal("root changed")
	}
}

func TestRootInitFailures(t *testing.T) {
	// An orphan backup (from an earlier root) is never overwritten.
	h := start(t)
	os.MkdirAll(filepath.Dir(h.s.BackupPath), 0o700)
	os.WriteFile(h.s.BackupPath, []byte("old"), 0o600)
	if code, _ := h.call("POST", "/v1/root/init", nil); code != http.StatusConflict {
		t.Fatalf("orphan backup: %d", code)
	}
	if b, _ := os.ReadFile(h.s.BackupPath); string(b) != "old" {
		t.Fatal("orphan backup overwritten")
	}
	if ok, _ := h.s.Store.Exists(); ok {
		t.Fatal("key saved despite failure")
	}

	// Backup directory cannot be created / backup path unwritable.
	h = start(t)
	f := filepath.Join(h.dir, "file")
	os.WriteFile(f, nil, 0o600)
	h.s.BackupPath = filepath.Join(f, "x", "backup.json") // parent is a file
	if code, _ := h.call("POST", "/v1/root/init", nil); code != 500 {
		t.Fatalf("mkdir fail: %d", code)
	}
	// An unexpected write failure is a 500 and leaves no key behind.
	h.s.BackupPath = filepath.Join(h.dir, "backup.json")
	oldCreate := createFile
	createFile = func(string) (io.WriteCloser, error) { return nil, errors.New("disk") }
	code, _ := h.call("POST", "/v1/root/init", nil)
	createFile = oldCreate
	if code != 500 {
		t.Fatalf("backup write fail: %d", code)
	}
	if ok, _ := h.s.Store.Exists(); ok {
		t.Fatal("key saved after a failed backup")
	}

	// Store failures: save error cleans the backup up.
	h = start(t)
	h.s.Store = failStore{FileStore: root.FileStore{Dir: h.dir}, save: errors.New("disk")}
	if code, _ := h.call("POST", "/v1/root/init", nil); code != 500 {
		t.Fatalf("save fail: %d", code)
	}
	if _, err := os.Stat(h.s.BackupPath); err == nil {
		t.Fatal("backup left behind after failed save")
	}
	h.s.Store = failStore{FileStore: root.FileStore{Dir: h.dir}, save: root.ErrExists}
	if code, _ := h.call("POST", "/v1/root/init", nil); code != 409 {
		t.Fatalf("racing save: %d", code)
	}
	h.s.Store = failStore{FileStore: root.FileStore{Dir: h.dir}, exists: errors.New("io")}
	if code, _ := h.call("POST", "/v1/root/init", nil); code != 500 {
		t.Fatalf("exists fail: %d", code)
	}
	if code, _ := h.call("POST", "/v1/root/recover", map[string]string{"recovery_code": "x"}); code != 500 {
		t.Fatalf("recover exists fail: %d", code)
	}
	h.s.Store = failStore{FileStore: root.FileStore{Dir: h.dir}, load: errors.New("io")}
	if code, _ := h.call("GET", "/v1/root", nil); code != 500 {
		t.Fatalf("status load fail: %d", code)
	}
	if code, _ := h.call("POST", "/v1/bindings/sign", map[string]any{}); code != 500 {
		t.Fatalf("sign load fail: %d", code)
	}
}

type failStore struct {
	root.FileStore
	save, exists, load error
}

func (f failStore) Save(k ed25519.PrivateKey) error {
	if f.save != nil {
		return f.save
	}
	return f.FileStore.Save(k)
}
func (f failStore) Exists() (bool, error) {
	if f.exists != nil {
		return false, f.exists
	}
	return f.FileStore.Exists()
}
func (f failStore) Load() (ed25519.PrivateKey, error) {
	if f.load != nil {
		return nil, f.load
	}
	return f.FileStore.Load()
}

// failWriter fails at the step named, so writeNew's cleanup is exercised.
type failWriter struct{ failWrite, failClose bool }

func (f failWriter) Write(p []byte) (int, error) {
	if f.failWrite {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}
func (f failWriter) Close() error {
	if f.failClose {
		return errors.New("close failed")
	}
	return nil
}

func TestWriteNewFailures(t *testing.T) {
	old := createFile
	defer func() { createFile = old }()
	for name, fw := range map[string]failWriter{"write": {failWrite: true}, "close": {failClose: true}} {
		path := filepath.Join(t.TempDir(), "f")
		createFile = func(p string) (io.WriteCloser, error) {
			os.WriteFile(p, []byte("partial"), 0o600)
			return fw, nil
		}
		if err := writeNew(path, []byte("x")); err == nil {
			t.Errorf("%s: no error", name)
		}
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s: partial file left behind", name)
		}
	}
	createFile = old
	if err := writeNew(t.TempDir(), []byte("x")); err == nil {
		t.Fatal("writing to a directory succeeded")
	}
	path := filepath.Join(t.TempDir(), "ok")
	if err := writeNew(path, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(path, []byte("y")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwrite: %v", err)
	}
}

func TestRootCreationFailure(t *testing.T) {
	h := start(t)
	old := newRoot
	newRoot = func() (*root.Root, error) { return nil, errors.New("entropy") }
	defer func() { newRoot = old }()
	if code, _ := h.call("POST", "/v1/root/init", nil); code != 500 {
		t.Fatalf("code %d", code)
	}
	if ok, _ := h.s.Store.Exists(); ok {
		t.Fatal("root saved after a failed creation")
	}
}

func TestNewSecret(t *testing.T) {
	a, b := NewSecret(), NewSecret()
	if len(a) < 26 || a == b {
		t.Fatalf("weak or repeated secret: %q %q", a, b)
	}
}

// TestNoSecretsInAnyResponse drives every endpoint, including failures, and
// checks that nothing but init's one-time recovery code ever carries the root
// key (seed or full private key, raw, base64 or hex), the recovery code or the
// session secret.
func TestNoSecretsInAnyResponse(t *testing.T) {
	h := start(t)
	r := h.init()
	h.call("POST", "/v1/root/init", nil) // refused
	h.call("GET", "/v1/root", nil)
	pub, _, _ := ed25519.GenerateKey(nil)
	h.call("POST", "/v1/bindings/sign", bindingReq{Tenant: "t", ID: "d", Owner: "o", SigningKey: pub, Version: 1})
	h.call("POST", "/v1/bindings/sign", bindingReq{Tenant: "t"})
	h.call("POST", "/v1/revocations/sign", revocationReq{Tenant: "t", Add: []string{"d"}})
	h.call("POST", "/v1/root/recover", recoverReq{RecoveryCode: r.RecoveryCode}) // refused: root exists
	os.Remove(filepath.Join(h.dir, "root.key"))
	h.call("POST", "/v1/root/recover", recoverReq{RecoveryCode: "WRONG"})
	h.call("POST", "/v1/root/recover", recoverReq{RecoveryCode: r.RecoveryCode})
	rawPost(h, "/v1/root/recover", "{bad")

	k, err := root.FileStore{Dir: h.dir}.Load()
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string][]byte{"recovery code": []byte(r.RecoveryCode), "session secret": []byte(h.s.Secret)}
	for name, v := range map[string][]byte{"seed": k.Seed(), "private key": k} {
		secrets[name] = v
		secrets[name+" base64"] = []byte(base64.StdEncoding.EncodeToString(v))
		secrets[name+" hex"] = []byte(hex.EncodeToString(v))
	}
	for path, bodies := range h.seen {
		for _, b := range bodies {
			for name, needle := range secrets {
				if name == "recovery code" && path == "/v1/root/init" && bytes.Contains(b, []byte(`"recovery_code"`)) {
					continue // the one allowed place
				}
				if bytes.Contains(b, needle) {
					t.Errorf("%s response carries the %s: %s", path, name, b)
				}
			}
		}
	}
	// The one-time code appears only on the first init reply, not on the refused retry.
	if got := h.seen["/v1/root/init"]; len(got) != 2 || !bytes.Contains(got[0], []byte(r.RecoveryCode)) || bytes.Contains(got[1], []byte("recovery_code")) {
		t.Errorf("init replies: %q", got)
	}
}

func TestSignBinding(t *testing.T) {
	h := start(t)
	r := h.init()
	pub, _, _ := ed25519.GenerateKey(nil)
	req := bindingReq{Tenant: "t1", ID: "dev-1", Owner: "a@example.com", SigningKey: pub, Version: 3}
	code, b := h.call("POST", "/v1/bindings/sign", req)
	if code != 200 {
		t.Fatalf("sign: %d %s", code, b)
	}
	var sb binding.Signed
	json.Unmarshal(b, &sb)
	k, _ := root.FileStore{Dir: h.dir}.Load()
	if err := binding.Verify(k.Public().(ed25519.PublicKey), &sb, fixedNow); err != nil {
		t.Fatalf("binding does not verify: %v", err)
	}
	if sb.DeviceID != "dev-1" || sb.Version != 3 || !sb.NotAfter.Equal(fixedNow.Add(binding.Lifetime)) {
		t.Fatalf("binding fields: %+v", sb.Binding)
	}
	// The signer picks the expiry: a caller-supplied one is not accepted.
	raw := `{"tenant":"t1","id":"d","owner":"o","signing_key":"` + "AAAA" + `","version":1,"not_after":"2099-01-01T00:00:00Z"}`
	if code := rawPost(h, "/v1/bindings/sign", raw); code != 400 {
		t.Errorf("caller-chosen not_after: %d", code)
	}
	// Invalid input (bad key length) is a 400, not a signature.
	req.SigningKey = []byte("short")
	if code, _ := h.call("POST", "/v1/bindings/sign", req); code != 400 {
		t.Errorf("bad key: %d", code)
	}
	if code := rawPost(h, "/v1/bindings/sign", "{not json"); code != 400 {
		t.Errorf("bad json: %d", code)
	}
	assertNoSecrets(t, h, r, b)
}

func rawPost(h *harness, path, body string) int {
	req, _ := http.NewRequest("POST", h.url+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+h.s.Secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestSignRevocation(t *testing.T) {
	h := start(t)
	h.init()
	k, _ := root.FileStore{Dir: h.dir}.Load()
	pub := k.Public().(ed25519.PublicKey)

	code, b := h.call("POST", "/v1/revocations/sign", revocationReq{Tenant: "t1", Add: []string{"dev-2", "dev-1"}})
	if code != 200 {
		t.Fatalf("first list: %d %s", code, b)
	}
	var l1 revocation.Signed
	json.Unmarshal(b, &l1)
	if err := revocation.Verify(pub, &l1, fixedNow); err != nil || l1.Version != 1 || len(l1.Revoked) != 2 {
		t.Fatalf("first list: %v %+v", err, l1.List)
	}
	code, b = h.call("POST", "/v1/revocations/sign", revocationReq{Tenant: "t1", Prev: &l1, Add: []string{"dev-3"}})
	var l2 revocation.Signed
	json.Unmarshal(b, &l2)
	if code != 200 || l2.Version != 2 || len(l2.Revoked) != 3 {
		t.Fatalf("second list: %d %s", code, b)
	}
	// A refresh adds nothing.
	_, b = h.call("POST", "/v1/revocations/sign", revocationReq{Tenant: "t1", Prev: &l2})
	var l3 revocation.Signed
	json.Unmarshal(b, &l3)
	if l3.Version != 3 || len(l3.Revoked) != 3 {
		t.Fatalf("refresh: %+v", l3.List)
	}
	// A list signed by some other key is refused.
	_, other, _ := ed25519.GenerateKey(nil)
	foreign, _ := revocation.Next(other, "t1", nil, []string{"x"}, fixedNow)
	if code, _ := h.call("POST", "/v1/revocations/sign", revocationReq{Tenant: "t1", Prev: foreign}); code != 400 {
		t.Errorf("foreign prev: %d", code)
	}
	// A previous list for another tenant is refused.
	if code, _ := h.call("POST", "/v1/revocations/sign", revocationReq{Tenant: "t2", Prev: &l1}); code != 400 {
		t.Errorf("wrong tenant: %d", code)
	}
	if code := rawPost(h, "/v1/revocations/sign", "[]"); code != 400 {
		t.Errorf("bad json: %d", code)
	}
}

func TestRecovery(t *testing.T) {
	h := start(t)
	r := h.init()
	keyFile := filepath.Join(h.dir, "root.key")
	backup, _ := os.ReadFile(h.s.BackupPath)

	// With a root present, recovery refuses and changes nothing.
	if code, _ := h.call("POST", "/v1/root/recover", recoverReq{RecoveryCode: r.RecoveryCode}); code != http.StatusConflict {
		t.Fatalf("recover over a root: %d", code)
	}

	os.Remove(keyFile) // lost the key, kept the backup
	if code, _ := h.call("POST", "/v1/root/recover", recoverReq{RecoveryCode: "WRONG-CODE"}); code != http.StatusForbidden {
		t.Fatalf("wrong code: %d", code)
	}
	if ok, _ := h.s.Store.Exists(); ok {
		t.Fatal("wrong code stored a key")
	}
	code, b := h.call("POST", "/v1/root/recover", recoverReq{RecoveryCode: r.RecoveryCode})
	var st statusResp
	json.Unmarshal(b, &st)
	if code != 200 || st.Fingerprint != r.Fingerprint {
		t.Fatalf("recover from file: %d %s", code, b)
	}
	if strings.Contains(string(b), r.RecoveryCode) {
		t.Fatal("recovery code echoed")
	}

	// Recovery from supplied backup content, when the file is gone.
	os.Remove(keyFile)
	os.Remove(h.s.BackupPath)
	if code, _ := h.call("POST", "/v1/root/recover", recoverReq{RecoveryCode: r.RecoveryCode}); code != http.StatusNotFound {
		t.Fatalf("no backup: %d", code)
	}
	code, b = h.call("POST", "/v1/root/recover", recoverReq{RecoveryCode: r.RecoveryCode, Backup: backup})
	if code != 200 {
		t.Fatalf("recover from content: %d %s", code, b)
	}
	if code := rawPost(h, "/v1/root/recover", `{"surprise":1}`); code != 400 {
		t.Errorf("unknown field: %d", code)
	}

	// A save that loses a race maps to 409; other failures to 500.
	os.Remove(keyFile)
	h.s.Store = failStore{FileStore: root.FileStore{Dir: h.dir}, save: root.ErrExists}
	if code, _ := h.call("POST", "/v1/root/recover", recoverReq{RecoveryCode: r.RecoveryCode, Backup: backup}); code != 409 {
		t.Errorf("racing recover: %d", code)
	}
	h.s.Store = failStore{FileStore: root.FileStore{Dir: h.dir}, save: errors.New("disk")}
	if code, _ := h.call("POST", "/v1/root/recover", recoverReq{RecoveryCode: r.RecoveryCode, Backup: backup}); code != 500 {
		t.Errorf("failing recover: %d", code)
	}
}

func TestDefaultClock(t *testing.T) {
	s := &Server{}
	if d := time.Since(s.now()); d < 0 || d > time.Minute {
		t.Fatalf("default clock off by %v", d)
	}
}

// assertNoSecrets: no browser-bound response may carry the root key seed,
// the private key or the recovery code, except init's one-time code.
func assertNoSecrets(t *testing.T, h *harness, r initResp, bodies ...[]byte) {
	t.Helper()
	k, _ := root.FileStore{Dir: h.dir}.Load()
	seed := k.Seed()
	for _, b := range bodies {
		s := string(b)
		for _, needle := range []string{r.RecoveryCode, string(seed), string(k), encode(seed), encode(k)} {
			if strings.Contains(s, needle) {
				t.Fatalf("response leaks a secret: %s", s)
			}
		}
	}
}

func encode(b []byte) string {
	j, _ := json.Marshal(b)
	return strings.Trim(string(j), `"`)
}

// TestReusesRootPackages pins the acceptance claim that the signer signs with
// the existing packages rather than its own crypto.
func TestReusesRootPackages(t *testing.T) {
	src, err := os.ReadFile("signer.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"internal/root", "internal/revocation", "internal/trust"} {
		if !strings.Contains(string(src), `"github.com/kalahroudi/parley/`+p+`"`) {
			t.Errorf("signer does not import %s", p)
		}
	}
	if strings.Contains(string(src), "ed25519.Sign(") {
		t.Error("signer signs directly instead of through the packages")
	}
}
