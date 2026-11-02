// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/revocation"
)

// FuzzGatewayReplies makes a malicious gateway answer every client call with
// an arbitrary status and body. Whatever it says, the client must not panic or
// hang, must return an error rather than a half-decoded value for a failure
// status, and anything it hands back must be safe to pass on to the verifiers
// (binding.Verify and revocation.Verify take the decoded structs as they are).
func FuzzGatewayReplies(f *testing.F) {
	var mu sync.Mutex
	var code int
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		c, b := code, body
		mu.Unlock()
		w.WriteHeader(c)
		w.Write(b)
	}))
	f.Cleanup(srv.Close)
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	now := time.Unix(1_800_000_000, 0)

	f.Add(200, []byte(`{"id":"a","poll":"b","status":"approved","fingerprint":"ff","pending":[{"id":"1","signing_key":"AAAA"}]}`))
	f.Add(200, []byte(`{"status":"approved","binding":{"tenant":"t","owner":"o","device_id":"d","signing_key":"AAAA","version":1,"not_after":"2030-01-01T00:00:00Z","signature":"AAAA"}}`))
	f.Add(200, []byte(`{"tenant":"t1","version":2,"issued_at":"2027-01-01T00:00:00Z","revoked":["a"],"signature":"AAAA"}`))
	f.Add(200, []byte(`null`))
	f.Add(200, []byte(`[]`))
	f.Add(200, []byte(`{"binding":null,"pending":null}`))
	f.Add(404, []byte(`{}`))
	f.Add(500, []byte(`{"status":"approved"}`))
	f.Add(200, []byte(`{"status":`))
	f.Fuzz(func(t *testing.T, status int, reply []byte) {
		if status < 200 || status > 599 {
			status = 200
		}
		mu.Lock()
		code, body = status, reply
		mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ok := status/100 == 2

		id, poll, err := c.RequestEnrollment(ctx, "n", pub)
		if !ok && (err == nil || id != "" || poll != "") {
			t.Fatalf("failure status %d returned a value: %q %q %v", status, id, poll, err)
		}
		st, err := c.EnrollmentStatus(ctx, "t", "id", "poll")
		if !ok && (err == nil || st != nil) {
			t.Fatalf("failure status %d returned a status", status)
		}
		if st != nil && st.Binding != nil {
			_ = binding.Verify(pub, st.Binding, now)
		}
		ps, err := c.Pending(ctx)
		if !ok && err == nil {
			t.Fatalf("failure status %d listed pending requests: %v", status, ps)
		}
		l, err := c.FetchRevocations(ctx, "t1")
		if !ok && (err == nil || l != nil) {
			t.Fatalf("failure status %d returned a revocation list", status)
		}
		if l != nil {
			_ = revocation.Verify(pub, l, now)
		}
		if err := c.Decide(ctx, "id", "approved"); !ok && err == nil {
			t.Fatalf("failure status %d reported a decision as recorded", status)
		}
	})
}
