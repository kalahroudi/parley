// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package connect

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// FuzzReplies feeds the gateway's answers, whatever they are, to the client. The gateway is untrusted here: the
// client must never panic, never return a token on a failure status or from a reply that lacks one, and never put
// any part of the reply in an error (a reply may echo a credential).
func FuzzReplies(f *testing.F) {
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
	client := &Client{BaseURL: srv.URL, Tenant: "t", Device: "d", HTTP: srv.Client()}
	_, priv, _ := ed25519.GenerateKey(nil)

	f.Add(200, []byte(`{"challenge":"abc","expires_at":1700000000000,"token":"pdt_t.d.s","expires_at_":1}`))
	f.Add(200, []byte(`{"token":"pdt_t.d.secret","expires_at":1700000000000}`))
	f.Add(200, []byte(`{"challenge":"","expires_at":0}`))
	f.Add(401, []byte(`{"error":"unauthorized","token":"pdt_leak"}`))
	f.Add(429, []byte(`{"error":"rate_limited"}`))
	f.Add(200, []byte(`null`))
	f.Add(200, []byte(`{"challenge":`))
	f.Fuzz(func(t *testing.T, status int, reply []byte) {
		if status < 200 || status > 599 { // 1xx is an interim response, never the final one
			status = 200
		}
		mu.Lock()
		code, body = status, reply
		mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tok, err := client.Token(ctx, priv, 1, ScopeConnect)
		if err != nil {
			if tok != (Token{}) {
				t.Fatalf("an error came with a token")
			}
			for _, leak := range []string{"pdt_", "secret"} {
				if strings.Contains(err.Error(), leak) && strings.Contains(string(reply), leak) {
					t.Fatalf("the reply reached the error: %v", err)
				}
			}
			return
		}
		if status != 200 || tok.Secret == "" || tok.ExpiresAt.IsZero() {
			t.Fatalf("status %d produced %+v", status, tok)
		}
	})
}
