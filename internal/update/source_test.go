// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestValidSource(t *testing.T) {
	for _, s := range []string{DefaultSource, "https://mirror.example/parley", "http://127.0.0.1:8080/x", "http://localhost/x", "http://[::1]:9/x"} {
		if err := ValidSource(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "http://example.com/x", "ftp://example.com", "https://", "https://u:p@example.com/x", "https://example.com/x?a=b", "https://example.com/x#f", "file:///etc", "%", "http://127.0.0.1.example.com/", "http://10.0.0.1/x", "http://192.168.1.1/x", "http://[2001:db8::1]/x"} {
		if ValidSource(s) == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestHTTPSourceFetch(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/big"):
			w.Write(bytes.Repeat([]byte("x"), 100))
		case strings.HasSuffix(r.URL.Path, "/missing"):
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, "/redir"):
			http.Redirect(w, r, "/latest/download/ok", http.StatusFound)
		case strings.Contains(r.URL.Path, "/hop/"):
			n, _ := strconv.Atoi(r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
			if n == 0 {
				w.Write([]byte("ok"))
				return
			}
			http.Redirect(w, r, "/rel/latest/download/hop/"+strconv.Itoa(n-1), http.StatusFound)
		case strings.HasSuffix(r.URL.Path, "/loop"):
			http.Redirect(w, r, r.URL.Path, http.StatusFound)
		case strings.HasSuffix(r.URL.Path, "/away"):
			http.Redirect(w, r, "ftp://example.com/x", http.StatusFound)
		default:
			w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	s := HTTPSource{Base: srv.URL + "/rel/"}
	ctx := context.Background()
	var b bytes.Buffer
	if err := s.Fetch(ctx, "", "ok", 10, &b); err != nil || b.String() != "ok" {
		t.Fatalf("latest: %v %q", err, b.String())
	}
	b.Reset()
	if err := s.Fetch(ctx, "v1.2.3", "ok", 10, &b); err != nil || b.String() != "ok" {
		t.Fatalf("version: %v", err)
	}
	if paths[0] != "/rel/latest/download/ok" || paths[1] != "/rel/download/v1.2.3/ok" {
		t.Fatalf("paths %v", paths)
	}
	if err := s.Fetch(ctx, "", "big", 99, &b); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("oversize: %v", err)
	}
	if err := s.Fetch(ctx, "", "big", 100, &bytes.Buffer{}); err != nil {
		t.Fatalf("exact size: %v", err)
	}
	if err := s.Fetch(ctx, "", "missing", 10, &b); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404: %v", err)
	}
	b.Reset()
	// A redirect from the release address to the asset host is followed...
	s2 := HTTPSource{Base: srv.URL + "/rel", Client: srv.Client()}
	if err := s2.Fetch(ctx, "", "redir", 10, &b); err != nil || b.String() != "ok" {
		t.Fatalf("redirect: %v", err)
	}
	// ...but not to an address we would not have been given, nor forever.
	if err := s.Fetch(ctx, "", "away", 10, &b); err == nil {
		t.Fatal("redirect to ftp followed")
	}
	// Four redirects are followed, a fifth is not.
	b.Reset()
	if err := s.Fetch(ctx, "", "hop/4", 10, &b); err != nil || b.String() != "ok" {
		t.Fatalf("four redirects: %v", err)
	}
	if err := s.Fetch(ctx, "", "hop/5", 10, &b); err == nil {
		t.Fatal("five redirects followed")
	}
	if err := s.Fetch(ctx, "", "loop", 10, &b); err == nil {
		t.Fatal("redirect loop followed")
	}
	if err := (HTTPSource{Base: "http://example.com"}).Fetch(ctx, "", "ok", 10, &b); err != ErrSource {
		t.Fatalf("plain http: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Fetch(cctx, "", "ok", 10, &b); err == nil {
		t.Fatal("canceled fetch succeeded")
	}
	// A body that dies half way is an error, not a short file.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "50")
		w.Write([]byte("short"))
	}))
	defer broken.Close()
	if err := (HTTPSource{Base: broken.URL}).Fetch(ctx, "", "x", 100, &bytes.Buffer{}); err == nil {
		t.Fatal("truncated body accepted")
	}
	if err := (HTTPSource{Base: "https://a b"}).Fetch(ctx, "", "x", 1, &b); err == nil {
		t.Fatal("bad base accepted")
	}
	if err := (HTTPSource{Base: "http://127.0.0.1:1/"}).Fetch(ctx, "v1\n", "x", 1, &b); err == nil {
		t.Fatal("bad url accepted")
	}
}

// The limits are part of the security posture (what an untrusted source can make us read), so they are pinned.
func TestLimitsArePinned(t *testing.T) {
	if maxSums != 64<<10 || maxSig != 4<<10 || maxBinary != 256<<20 || fetchTimeout != 10*time.Minute || maxSkew != 5*time.Minute || maxValidity != 400*24*time.Hour || maxUnix != 1<<40 {
		t.Fatal("a download limit changed: review it")
	}
}

// A release address on https must not bounce the download down to plain http, even to a loopback host.
func TestHTTPSourceRefusesDowngradeRedirect(t *testing.T) {
	hit := false
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Write([]byte("ok"))
	}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/down") {
			http.Redirect(w, r, plain.URL+"/x", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/rel/latest/download/ok", http.StatusFound)
	}))
	defer secure.Close()
	s := HTTPSource{Base: secure.URL + "/rel", Client: secure.Client()}
	if err := s.Fetch(context.Background(), "", "down", 10, &bytes.Buffer{}); err == nil || hit {
		t.Fatalf("https to http redirect followed (hit=%v, err=%v)", hit, err)
	}
}
