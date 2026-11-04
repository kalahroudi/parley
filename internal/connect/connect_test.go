// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The same bytes gateway/src/connect.ts builds; gateway/test/connect.test.ts checks this vector too.
const vector = "00000011" + "7061726c65792f636f6e6e6563742f7632" + // the label parley/connect/v2
	"00000002" + "7431" + "00000003" + "646576" + "00000002" + "6368" + // tenant t1, device dev, challenge ch
	"0000018bcfe56800" + "0000000000000003" + // expiry 1700000000000 ms, binding version 3
	"00000003" + "617069" // scope api

func TestMessageVector(t *testing.T) {
	if got := hex.EncodeToString(Message("t1", "dev", "ch", 1700000000000, 3, ScopeAPI)); got != vector {
		t.Fatalf("Message = %s, want %s", got, vector)
	}
	base := Message("ab", "c", "d", 1, 1, ScopeAPI)
	for name, other := range map[string][]byte{
		"shifted boundary": Message("a", "bc", "d", 1, 1, ScopeAPI),
		"expiry":           Message("ab", "c", "d", 2, 1, ScopeAPI),
		"version":          Message("ab", "c", "d", 1, 2, ScopeAPI),
		"scope":            Message("ab", "c", "d", 1, 1, ScopeConnect),
		"challenge":        Message("ab", "c", "e", 1, 1, ScopeAPI),
		"tenant":           Message("ac", "c", "d", 1, 1, ScopeAPI),
		"device":           Message("ab", "d", "d", 1, 1, ScopeAPI),
	} {
		if string(base) == string(other) {
			t.Errorf("a change of %s signs the same bytes", name)
		}
	}
}

// fakeGateway is the gateway's side of the protocol: a challenge, then a token for a valid signature.
type fakeGateway struct {
	pub      ed25519.PublicKey
	srv      *httptest.Server
	tokens   atomic.Int32
	override func(path string, w http.ResponseWriter) bool // a test's own answer; true when it answered
	seen     []map[string]any
}

func newGateway(t *testing.T, pub ed25519.PublicKey) *fakeGateway {
	g := &fakeGateway{pub: pub}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &b)
		g.seen = append(g.seen, b)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad", 400)
			return
		}
		if g.override != nil && g.override(r.URL.Path, w) {
			return
		}
		switch r.URL.Path {
		case "/v1/connect/challenge":
			fmt.Fprint(w, `{"challenge":"abc","expires_at":1700000000000}`)
		case "/v1/connect/token":
			var in struct {
				Tenant, Device, Challenge string
				Version                   uint64
				Scope                     Scope
				Signature                 []byte
			}
			_ = json.Unmarshal(raw, &in)
			if !ed25519.Verify(g.pub, Message(in.Tenant, in.Device, in.Challenge, 1700000000000, in.Version, in.Scope), in.Signature) {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"error":"unauthorized"}`)
				return
			}
			g.tokens.Add(1)
			fmt.Fprintf(w, `{"token":"pdt_t.d.secret","expires_at":%d}`, time.Now().Add(5*time.Minute).UnixMilli())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestTokenProvesPossessionOfTheKey(t *testing.T) {
	pub, priv := key(t)
	g := newGateway(t, pub)
	c := &Client{BaseURL: g.srv.URL + "/", Tenant: "t", Device: "d"}
	tok, err := c.Token(context.Background(), priv, 1, ScopeAPI)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Secret != "pdt_t.d.secret" || time.Until(tok.ExpiresAt) < 4*time.Minute || time.Until(tok.ExpiresAt) > 5*time.Minute {
		t.Fatalf("token = %+v", tok)
	}
	if len(g.seen) != 2 || g.seen[0]["tenant"] != "t" || g.seen[1]["device"] != "d" || g.seen[1]["challenge"] != "abc" || g.seen[1]["version"] != float64(1) || g.seen[1]["scope"] != "api" {
		t.Fatalf("requests = %v", g.seen)
	}
	if _, ok := g.seen[0]["signature"]; ok {
		t.Fatal("the challenge request carries a signature")
	}

	// Another key is refused, with the one error and without the body.
	_, other := key(t)
	_, err = c.Token(context.Background(), other, 1, ScopeAPI)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
}

func TestTokenIsNotReadable(t *testing.T) {
	tok := Token{Secret: "pdt_secret-value"}
	for _, s := range []string{fmt.Sprint(tok), fmt.Sprintf("%v %+v %#v %s", tok, tok, tok, tok)} {
		if strings.Contains(s, "secret-value") {
			t.Fatalf("a formatted token shows its secret: %s", s)
		}
	}
}

func TestTokenRefusesBadRequestsWithoutCallingTheGateway(t *testing.T) {
	_, priv := key(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Tenant: "t", Device: "d"}
	for name, tc := range map[string]struct {
		v uint64
		s Scope
	}{"no version": {0, ScopeAPI}, "no scope": {1, ""}, "unknown scope": {1, "admin"}} {
		if _, err := c.Token(context.Background(), priv, tc.v, tc.s); !errors.Is(err, ErrRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("the gateway was called with an invalid request")
	}
}

func TestTokenRefusesBadKeysWithoutCallingTheGateway(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Tenant: "t", Device: "d"}
	for _, k := range []ed25519.PrivateKey{nil, make(ed25519.PrivateKey, 31), make(ed25519.PrivateKey, 65)} {
		if _, err := c.Token(context.Background(), k, 1, ScopeAPI); !errors.Is(err, ErrKey) {
			t.Errorf("key of %d bytes: %v", len(k), err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("the gateway was called with an invalid key")
	}
}

func TestTokenGatewayMisbehaviour(t *testing.T) {
	pub, priv := key(t)
	big := strings.Repeat("a", maxResponse+1)
	// One gateway for every case (the subtests run one after another): a server per case would burn thousands of local
	// ports under `go test -count=500`.
	g := newGateway(t, pub)
	for name, tc := range map[string]struct {
		path   string // the step that misbehaves
		status int
		body   string
		want   error  // errors.Is target, when there is one
		text   string // else the error must say this
	}{
		"challenge refused":        {"/v1/connect/challenge", 401, `{"error":"unauthorized"}`, ErrRefused, ""},
		"challenge forbidden":      {"/v1/connect/challenge", 403, ``, ErrRefused, ""},
		"token forbidden":          {"/v1/connect/token", 403, ``, ErrRefused, ""},
		"token server error":       {"/v1/connect/token", 500, `boom pdt_leak`, nil, "answered 500"},
		"challenge redirect":       {"/v1/connect/challenge", 307, ``, nil, "answered 307"},
		"challenge not json":       {"/v1/connect/challenge", 200, `<html>`, ErrReply, ""},
		"challenge empty":          {"/v1/connect/challenge", 200, `{"challenge":""}`, ErrReply, ""},
		"challenge missing":        {"/v1/connect/challenge", 200, `{}`, ErrReply, ""},
		"challenge without expiry": {"/v1/connect/challenge", 200, `{"challenge":"abc"}`, ErrReply, ""},
		"challenge rate limited":   {"/v1/connect/challenge", 429, `{"error":"rate_limited"}`, ErrRateLimited, ""},
		"token rate limited":       {"/v1/connect/token", 429, ``, ErrRateLimited, ""},
		"challenge too large":      {"/v1/connect/challenge", 200, `{"challenge":"` + big + `"}`, ErrReply, ""},
		"token not json":           {"/v1/connect/token", 200, `nope`, ErrReply, ""},
		"token empty":              {"/v1/connect/token", 200, `{"token":"","expires_at":5}`, ErrReply, ""},
		"token without expiry":     {"/v1/connect/token", 200, `{"token":"pdt_x"}`, ErrReply, ""},
		"token with negative time": {"/v1/connect/token", 200, `{"token":"pdt_x","expires_at":-1}`, ErrReply, ""},
		"token too large":          {"/v1/connect/token", 200, `{"token":"` + big + `","expires_at":5}`, ErrReply, ""},
	} {
		t.Run(name, func(t *testing.T) {
			g.override = func(path string, w http.ResponseWriter) bool {
				if path != tc.path {
					return false
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
				return true
			}
			_, err := (&Client{BaseURL: g.srv.URL, Tenant: "t", Device: "d"}).Token(context.Background(), priv, 1, ScopeAPI)
			switch {
			case err == nil:
				t.Fatal("no error")
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("err = %v, want %v", err, tc.want)
			case tc.text != "" && !strings.Contains(err.Error(), tc.text):
				t.Fatalf("err = %v, want it to say %q", err, tc.text)
			case strings.Contains(err.Error(), "leak"):
				t.Fatalf("the gateway's body reached the error: %v", err)
			}
		})
	}
}

func TestTokenTransportFailures(t *testing.T) {
	_, priv := key(t)
	// Nothing listening.
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if _, err := (&Client{BaseURL: url, Tenant: "t", Device: "d"}).Token(context.Background(), priv, 1, ScopeAPI); err == nil {
		t.Fatal("no error for an unreachable gateway")
	}
	// A canceled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&Client{BaseURL: url, Tenant: "t", Device: "d"}).Token(ctx, priv, 1, ScopeAPI); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	// A URL that cannot be a request.
	if _, err := (&Client{BaseURL: "http://bad host\x7f", Tenant: "t", Device: "d"}).Token(context.Background(), priv, 1, ScopeAPI); err == nil {
		t.Fatal("no error for an invalid URL")
	}
	// A body that fails while it is read.
	torn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		fmt.Fprint(w, "{")
	}))
	defer torn.Close()
	if _, err := (&Client{BaseURL: torn.URL, Tenant: "t", Device: "d"}).Token(context.Background(), priv, 1, ScopeAPI); err == nil {
		t.Fatal("no error for a truncated reply")
	}
}

func TestTokenDoesNotFollowRedirects(t *testing.T) {
	_, priv := key(t)
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer gw.Close()
	_, err := (&Client{BaseURL: gw.URL, Tenant: "t", Device: "d"}).Token(context.Background(), priv, 1, ScopeAPI)
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("err = %v", err)
	}
	if elsewhere.Load() != 0 {
		t.Fatal("a redirect was followed")
	}
}

func TestTokenUsesTheSuppliedClientWithoutChangingIt(t *testing.T) {
	pub, priv := key(t)
	g := newGateway(t, pub)
	var used atomic.Bool
	hc := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		used.Store(true)
		return http.DefaultTransport.RoundTrip(r)
	})}
	if _, err := (&Client{BaseURL: g.srv.URL, Tenant: "t", Device: "d", HTTP: hc}).Token(context.Background(), priv, 1, ScopeAPI); err != nil {
		t.Fatal(err)
	}
	if !used.Load() {
		t.Fatal("the supplied client was not used")
	}
	if hc.CheckRedirect != nil {
		t.Fatal("the caller's client was modified")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTunnelURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://gw.example":             "wss://gw.example/v1/connect",
		"https://gw.example/":            "wss://gw.example/v1/connect",
		"http://127.0.0.1:8787":          "ws://127.0.0.1:8787/v1/connect",
		"https://gw.example/base/?q=1#f": "wss://gw.example/base/v1/connect",
	} {
		if got, err := TunnelURL(in); err != nil || got != want {
			t.Errorf("TunnelURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"ftp://x", "gw.example", "", "wss://gw.example", "http://bad host\x7f"} {
		if got, err := TunnelURL(in); err == nil {
			t.Errorf("TunnelURL(%q) = %q, want an error", in, got)
		}
	}
}
