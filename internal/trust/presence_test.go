// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPresence(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/directory/presence" || r.Header.Get("Authorization") != "Bearer me" {
			http.Error(w, "no", 500)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		switch got["id"] {
		case "online":
			w.Write([]byte(`{"online":true}`))
		case "offline":
			w.Write([]byte(`{"online":false}`))
		default:
			http.Error(w, "gone", 404)
		}
	}))
	t.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, Auth: "Bearer me"}
	ctx := context.Background()

	if on, err := c.Presence(ctx, "online"); err != nil || !on || got["id"] != "online" {
		t.Fatalf("online: %v %v %v", on, err, got)
	}
	if on, err := c.Presence(ctx, "offline"); err != nil || on {
		t.Fatalf("offline: %v %v", on, err)
	}
	if _, err := c.Presence(ctx, "hidden"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("hidden card: %v", err)
	}
}

func TestRateLimited(t *testing.T) {
	for header, want := range map[string]time.Duration{
		"6":       6 * time.Second,
		" 2 ":     2 * time.Second,
		"1":       time.Second,
		"60":      time.Minute,
		"61":      time.Minute, // capped
		"999999":  time.Minute,
		"0":       time.Second, // never zero: a zero wait would be a busy loop
		"-5":      time.Second,
		"":        time.Second,
		"soon":    time.Second,
		"Wed, 21": time.Second,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if header != "" {
				w.Header().Set("Retry-After", header)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate_limited"}`))
		}))
		_, err := (&Client{BaseURL: srv.URL}).Presence(context.Background(), "x")
		srv.Close()
		var rl *RateLimitedError
		if !errors.As(err, &rl) || rl.RetryAfter() != want || errors.Is(err, ErrNotFound) {
			t.Fatalf("Retry-After %q: %v, want wait %s", header, err, want)
		}
		if rl.Error() == "" {
			t.Fatal("empty message")
		}
	}
}
