// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package caller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFindAgentsMarksCardsUntrustedAndValidatesTheQuery(t *testing.T) {
	r := newRig(t)
	p, err := r.s.FindAgents(context.Background(), Query{Text: "review", Limit: 5})
	if err != nil || !p.Untrusted || len(p.Agents) != 1 || p.Agents[0].Name != "review" {
		t.Fatalf("%+v %v", p, err)
	}
	for name, q := range map[string]Query{
		"text too long":   {Text: strings.Repeat("a", maxQuery+1)},
		"tag too long":    {Tag: strings.Repeat("a", maxTag+1)},
		"control in text": {Text: "a\nb"},
		"control in tag":  {Tag: "a\x7f"},
		"bad utf-8":       {Text: "\xff"},
		"negative limit":  {Limit: -1},
		"limit too big":   {Limit: MaxLimit + 1},
		"odd cursor":      {Cursor: "abc"},
		"non-hex cursor":  {Cursor: "zz"},
		"upper-case":      {Cursor: "AB"},
		"cursor too long": {Cursor: strings.Repeat("ab", 801)},
	} {
		if _, err := r.s.FindAgents(context.Background(), q); code(err) != CodeBadParams {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestFindAgentsErrorsAreFixedAndLimited(t *testing.T) {
	r := newRig(t)
	r.s.cfg.Find = func(context.Context, Query) (*Page, error) { return nil, errors.New("gateway said SECRET") }
	if _, err := r.s.FindAgents(context.Background(), Query{}); code(err) != CodeDirectory {
		t.Fatal(err)
	}
	r.s.cfg.Find = nil
	if _, err := r.s.FindAgents(context.Background(), Query{}); code(err) != CodeDirectory {
		t.Fatal(err)
	}
	r.s.cfg.Find = func(context.Context, Query) (*Page, error) { return &Page{}, nil }
	var limited error
	for i := 0; i < FindsPerMinute+1 && limited == nil; i++ {
		_, limited = r.s.FindAgents(context.Background(), Query{})
	}
	if code(limited) != CodeRateLimit {
		t.Fatalf("no limit: %v", limited)
	}
}

type gw struct {
	srv      *httptest.Server
	tokens   atomic.Int32
	requests atomic.Int32
	status   atomic.Int32
	body     atomic.Value
	lastAuth atomic.Value
	lastBody atomic.Value
}

func newGW(t *testing.T) (*gw, *Directory) {
	g := &gw{}
	g.status.Store(200)
	g.body.Store(`{"agents":[{"id":"d:1","device_id":"d","owner":"o@x","name":"n","description":"x","tags":["t"],"examples":[]}],"next_cursor":"ab"}`)
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.requests.Add(1)
		b, _ := io.ReadAll(r.Body)
		g.lastAuth.Store(r.Header.Get("Authorization"))
		g.lastBody.Store(string(b))
		if r.URL.Path != "/v1/directory/find" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(int(g.status.Load()))
		io.WriteString(w, g.body.Load().(string))
	}))
	t.Cleanup(g.srv.Close)
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	return g, &Directory{BaseURL: g.srv.URL + "/", Now: clk.now, Token: func(context.Context) (string, time.Time, error) {
		n := g.tokens.Add(1)
		return "tok" + string(rune('0'+n)), clk.now().Add(time.Hour), nil
	}}
}

func TestDirectoryFindSendsTheQueryWithABearerTokenAndCachesIt(t *testing.T) {
	g, d := newGW(t)
	p, err := d.Find(context.Background(), Query{Text: "rev", Tag: "go", Limit: 10, Cursor: "ab"})
	if err != nil || len(p.Agents) != 1 || p.Agents[0].Owner != "o@x" || p.NextCursor != "ab" {
		t.Fatalf("%+v %v", p, err)
	}
	if g.lastAuth.Load() != "Bearer tok1" {
		t.Errorf("auth %v", g.lastAuth.Load())
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(g.lastBody.Load().(string)), &sent); err != nil || sent["limit"] != float64(10) || sent["cursor"] != "ab" || sent["query"].(map[string]any)["text"] != "rev" || sent["query"].(map[string]any)["tag"] != "go" {
		t.Errorf("body %v %v", sent, err)
	}
	if _, err := d.Find(context.Background(), Query{}); err != nil || g.tokens.Load() != 1 {
		t.Errorf("token not cached: %d %v", g.tokens.Load(), err)
	}
	if b := g.lastBody.Load().(string); b != "{}" {
		t.Errorf("an empty query must send an empty body, got %s", b)
	}
	// Only text, or only a tag.
	d.Find(context.Background(), Query{Text: "a"})
	if b := g.lastBody.Load().(string); b != `{"query":{"text":"a"}}` {
		t.Error(b)
	}
	d.Find(context.Background(), Query{Tag: "b"})
	if b := g.lastBody.Load().(string); b != `{"query":{"tag":"b"}}` {
		t.Error(b)
	}
}

func TestDirectoryFindRenewsAnExpiredTokenOnce(t *testing.T) {
	g, d := newGW(t)
	var first atomic.Bool
	g.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.requests.Add(1)
		if !first.Swap(true) {
			w.WriteHeader(401)
			return
		}
		g.lastAuth.Store(r.Header.Get("Authorization"))
		io.WriteString(w, `{"agents":null}`)
	})
	p, err := d.Find(context.Background(), Query{})
	if err != nil || p.Agents == nil || len(p.Agents) != 0 || g.tokens.Load() != 2 || g.lastAuth.Load() != "Bearer tok2" {
		t.Fatalf("%+v %v tokens=%d auth=%v", p, err, g.tokens.Load(), g.lastAuth.Load())
	}
	// A second 401 is final.
	g.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	d.secret = ""
	if _, err := d.Find(context.Background(), Query{}); err == nil {
		t.Fatal("a refused token was accepted")
	}
}

func TestDirectoryFindFailsClosedWithFixedErrors(t *testing.T) {
	g, d := newGW(t)
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"server error": {500, `{"error":"SECRET"}`},
		"not found":    {404, ``},
		"not json":     {200, `<html>SECRET`},
		"too many":     {200, `{"agents":[` + strings.Repeat(`{},`, MaxLimit) + `{}]}`},
		"bad cursor":   {200, `{"agents":[],"next_cursor":"SECRET"}`},
		"long cursor":  {200, `{"agents":[],"next_cursor":"` + strings.Repeat("ab", maxCursor/2+1) + `"}`},
		"too large":    {200, `{"agents":[],"pad":"` + strings.Repeat("a", maxDirReply) + `"}`},
	} {
		g.status.Store(int32(tc.status))
		g.body.Store(tc.body)
		_, err := d.Find(context.Background(), Query{})
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A token that cannot be had, an empty token, an unreachable gateway, a bad URL.
	d.Token = func(context.Context) (string, time.Time, error) { return "", time.Time{}, errors.New("SECRET") }
	d.secret = ""
	if _, err := d.Find(context.Background(), Query{}); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("token error: %v", err)
	}
	d.Token = func(context.Context) (string, time.Time, error) { return "", time.Now().Add(time.Hour), nil }
	if _, err := d.Find(context.Background(), Query{}); err == nil {
		t.Error("an empty token was used")
	}
	d.Token = func(context.Context) (string, time.Time, error) { return "t", time.Now().Add(time.Hour), nil }
	g.srv.Close()
	if _, err := d.Find(context.Background(), Query{}); err == nil {
		t.Error("closed gateway")
	}
	d.BaseURL = "http://bad host/"
	if _, err := d.Find(context.Background(), Query{}); err == nil {
		t.Error("bad url")
	}
}

func TestDirectoryDoesNotFollowRedirectsWithTheToken(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	defer other.Close()
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer gw.Close()
	d := &Directory{BaseURL: gw.URL, HTTP: gw.Client(), Token: func(context.Context) (string, time.Time, error) { return "t", time.Now().Add(time.Hour), nil }}
	if _, err := d.Find(context.Background(), Query{}); err == nil || leaked.Load() {
		t.Fatalf("err=%v leaked=%v", err, leaked.Load())
	}
}

func TestDirectoryRefreshesTokenNearExpiry(t *testing.T) {
	g, d := newGW(t)
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	d.Now = clk.now
	d.Token = func(context.Context) (string, time.Time, error) {
		g.tokens.Add(1)
		return "t", clk.now().Add(time.Minute), nil
	}
	d.Find(context.Background(), Query{})
	clk.add(40 * time.Second) // inside the slack before expiry
	d.Find(context.Background(), Query{})
	if g.tokens.Load() != 2 {
		t.Fatalf("tokens %d", g.tokens.Load())
	}
	// Without a clock seam the real clock is used.
	d.Now = nil
	d.secret = ""
	d.Find(context.Background(), Query{})
}
