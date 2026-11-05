// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
)

func TestRequestSendsOnlyWhatWasGiven(t *testing.T) {
	var body map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		body = nil
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "i1", "poll": "p1"})
	}))
	defer srv.Close()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	id, poll, err := (&Client{BaseURL: srv.URL}).Request(context.Background(), EnrollRequest{Tenant: "acme", Token: "pet_x", Name: "pod", Key: pub, ID: "i0", Poll: "p0"})
	if err != nil || id != "i1" || poll != "p1" {
		t.Fatalf("%q %q %v", id, poll, err)
	}
	if body["tenant"] != "acme" || body["token"] != "pet_x" || body["name"] != "pod" || body["id"] != "i0" || body["poll"] != "p0" || auth != "" {
		t.Errorf("body %v auth %q", body, auth)
	}
	// A user request carries the identity in the header and none of the optional fields.
	if _, _, err := (&Client{BaseURL: srv.URL, Auth: "Bearer s"}).Request(context.Background(), EnrollRequest{Name: "n", Key: pub}); err != nil {
		t.Fatal(err)
	}
	if _, has := body["tenant"]; has || len(body) != 2 || auth != "Bearer s" {
		t.Errorf("body %v auth %q", body, auth)
	}
}

func TestFetchRoot(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, tc := range map[string]struct {
		code  int
		reply any
		want  error
	}{
		"ok":        {200, map[string]any{"root_public_key": []byte(pub)}, nil},
		"short key": {200, map[string]any{"root_public_key": []byte{1}}, ErrBadRoot},
		"no key":    {200, map[string]any{}, ErrBadRoot},
		"unknown":   {404, nil, ErrNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			var req map[string]string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&req)
				if r.URL.Path != "/v1/root" {
					t.Errorf("path %s", r.URL.Path)
				}
				w.WriteHeader(tc.code)
				_ = json.NewEncoder(w).Encode(tc.reply)
			}))
			defer srv.Close()
			got, err := (&Client{BaseURL: srv.URL}).FetchRoot(context.Background(), "acme")
			if !errors.Is(err, tc.want) || (tc.want == nil && !got.Equal(pub)) || req["tenant"] != "acme" {
				t.Fatalf("%v %v %v", got, err, req)
			}
		})
	}
}

// Await is what a restarted device calls: it needs no request, only the id and the secret it saved.
func TestAwaitResumesARequestAndReportsAnUnknownOne(t *testing.T) {
	rootPub, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	devPub, _, _ := ed25519.GenerateKey(rand.Reader)
	b, err := binding.Sign(rootKey, binding.Binding{Tenant: "acme", Owner: "a@b", DeviceID: "i1", SigningKey: devPub, Version: 1, NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	known := true
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !known {
			http.NotFound(w, r)
			return
		}
		polls++
		if polls == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "approved", "binding": b})
	}))
	defer srv.Close()
	tr, err := binding.NewTracker(rootPub, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{Tracker: tr, Client: &Client{BaseURL: srv.URL}, Tenant: "acme"}
	got, err := d.Await(context.Background(), "i1", "poll", devPub, time.Millisecond, time.Now)
	if err != nil || got.DeviceID != "i1" || polls != 2 {
		t.Fatalf("%v %v polls=%d", got, err, polls)
	}
	known = false
	if _, err := d.Await(context.Background(), "i1", "poll", devPub, time.Millisecond, time.Now); !errors.Is(err, ErrNotFound) {
		t.Errorf("an expired request: %v", err)
	}
}

func TestJitterIsBoundedAndSpread(t *testing.T) {
	poll := 400 * time.Millisecond
	distinct := map[time.Duration]bool{}
	for range 200 {
		j := jitter(poll)
		if j < 0 || j > poll/4 {
			t.Fatalf("jitter %v outside [0, %v]", j, poll/4)
		}
		distinct[j] = true
	}
	if len(distinct) < 10 {
		t.Errorf("only %d distinct jitters in 200 draws", len(distinct))
	}
}

func TestAwaitSleepsThePollPlusJitter(t *testing.T) {
	old := jitter
	defer func() { jitter = old }()
	var got time.Duration
	jitter = func(p time.Duration) time.Duration { got = p; return 60 * time.Millisecond }
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n++; n == 1 {
			w.Write([]byte(`{"status":"pending"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := &Daemon{Client: &Client{BaseURL: srv.URL, HTTP: srv.Client()}, Tenant: "t"}
	start := time.Now()
	_, err := d.Await(context.Background(), "i1", "poll", nil, 2*time.Millisecond, time.Now)
	if !errors.Is(err, ErrNotFound) || got != 2*time.Millisecond || time.Since(start) < 62*time.Millisecond {
		t.Errorf("err=%v jitter arg=%v elapsed=%v", err, got, time.Since(start))
	}
}
