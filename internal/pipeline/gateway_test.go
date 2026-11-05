// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/outbox"
)

type rpcServer struct {
	*httptest.Server
	mu    sync.Mutex
	calls []map[string]any
	auth  []string
	reply func(n int) (int, string)
}

func newRPC(t *testing.T, reply func(n int) (int, string)) *rpcServer {
	s := &rpcServer{reply: reply}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		s.mu.Lock()
		s.calls = append(s.calls, m)
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		n := len(s.calls)
		s.mu.Unlock()
		if r.URL.Path != "/a2a" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		code, body := s.reply(n)
		w.WriteHeader(code)
		io.WriteString(w, body)
	}))
	t.Cleanup(s.Close)
	return s
}

const okReply = `{"jsonrpc":"2.0","id":"x","result":{"task":{"id":"t"}}}`

func rpcErr(code int, extra string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":"x","error":{"code":%d,"message":"m"%s}}`, code, extra)
}

func tokenFn(count *atomic.Int32, life time.Duration) func(context.Context) (string, time.Time, error) {
	return func(context.Context) (string, time.Time, error) {
		n := count.Add(1)
		return fmt.Sprintf("tok%d", n), time.Now().Add(life), nil
	}
}

func TestA2ASendBuildsTheRequestTheGatewayExpects(t *testing.T) {
	s := newRPC(t, func(int) (int, string) { return 200, okReply })
	var n atomic.Int32
	a := &A2A{BaseURL: s.URL + "/", Token: tokenFn(&n, time.Hour)}
	for _, kind := range []string{"TASK", "REPLY", "STATUS", "RESULT"} {
		if err := a.Send(context.Background(), Outgoing{Wire: []byte("wire"), Kind: kind, Target: "bob", Seq: 3}); err != nil {
			t.Fatal(err)
		}
	}
	if n.Load() != 1 {
		t.Fatalf("the token was fetched %d times, want once (cached)", n.Load())
	}
	for i, want := range []string{"ROLE_USER", "ROLE_USER", "ROLE_AGENT", "ROLE_AGENT"} {
		c := s.calls[i]
		msg := c["params"].(map[string]any)["message"].(map[string]any)
		part := msg["parts"].([]any)[0].(map[string]any)
		meta := msg["metadata"].(map[string]any)["parley"].(map[string]any)
		raw, _ := base64.StdEncoding.DecodeString(part["raw"].(string))
		if c["jsonrpc"] != "2.0" || c["method"] != "SendMessage" || msg["role"] != want || part["mediaType"] != "application/vnd.parley.sealed" ||
			string(raw) != "wire" || meta["to"] != "bob" || meta["seq"] != float64(3) || len(msg["messageId"].(string)) != 32 {
			t.Fatalf("call %d: %v", i, c)
		}
		if s.auth[i] != "Bearer tok1" {
			t.Fatalf("auth %q", s.auth[i])
		}
	}
	// The gateway refuses fields it does not know: the message has exactly these.
	keys := map[string]bool{}
	for k := range s.calls[0]["params"].(map[string]any)["message"].(map[string]any) {
		keys[k] = true
	}
	if len(keys) != 4 || !keys["messageId"] || !keys["role"] || !keys["parts"] || !keys["metadata"] {
		t.Fatalf("keys %v", keys)
	}
}

func TestA2ACancelCarriesTheSealedCancel(t *testing.T) {
	s := newRPC(t, func(int) (int, string) { return 200, okReply })
	var n atomic.Int32
	a := &A2A{BaseURL: s.URL, Token: tokenFn(&n, time.Hour)}
	if err := a.Cancel(context.Background(), Outgoing{Wire: []byte("cancel"), Task: "abc", Kind: "CANCEL", Seq: 2}); err != nil {
		t.Fatal(err)
	}
	p := s.calls[0]["params"].(map[string]any)
	meta := p["metadata"].(map[string]any)["parley"].(map[string]any)
	part := meta["parts"].([]any)[0].(map[string]any)
	if s.calls[0]["method"] != "CancelTask" || p["id"] != "abc" || meta["seq"] != float64(2) || part["mediaType"] != "application/vnd.parley.sealed" || len(meta) != 3 {
		t.Fatalf("%v", s.calls[0])
	}
}

func TestA2AClassifiesTheGatewaysAnswers(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		check  func(error) bool
	}{
		{"offline is not-delivered", 200, rpcErr(-32010, ""), func(e error) bool { return errors.Is(e, outbox.ErrOffline) }},
		{"rate limited carries the wait", 429, rpcErr(-32016, `,"data":{"retry_after_ms":2500}`), func(e error) bool {
			var r *RateLimited
			return errors.As(e, &r) && r.RetryAfter() == 2500*time.Millisecond && errors.Is(e, outbox.ErrOffline) && r.Error() != ""
		}},
		{"a negative wait is no wait", 429, rpcErr(-32016, `,"data":{"retry_after_ms":-5}`), func(e error) bool {
			var r *RateLimited
			return errors.As(e, &r) && r.RetryAfter() == 0
		}},
		{"not permitted", 200, rpcErr(-32013, ""), func(e error) bool { return errors.Is(e, ErrNotPermitted) }},
		{"too large", 200, rpcErr(-32014, ""), func(e error) bool { return errors.Is(e, ErrGatewayTooLarge) }},
		{"any other error", 200, rpcErr(-32012, ""), func(e error) bool { return errors.Is(e, ErrGatewayRefused) && !errors.Is(e, outbox.ErrOffline) }},
		{"not JSON", 200, "<html>", func(e error) bool { return errors.Is(e, ErrGatewayFailed) }},
		{"HTTP error without a result", 500, `{"jsonrpc":"2.0"}`, func(e error) bool { return errors.Is(e, ErrGatewayFailed) }},
		{"no result", 200, `{"jsonrpc":"2.0","id":"x"}`, func(e error) bool { return errors.Is(e, ErrGatewayFailed) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newRPC(t, func(int) (int, string) { return c.status, c.body })
			var n atomic.Int32
			a := &A2A{BaseURL: s.URL, Token: tokenFn(&n, time.Hour)}
			err := a.Send(context.Background(), Outgoing{Wire: []byte("w"), Kind: "TASK", Target: "b"})
			if err == nil || !c.check(err) {
				t.Fatalf("%v", err)
			}
			// Nothing the gateway said is repeated.
			if strings.Contains(err.Error(), "<html>") || strings.Contains(err.Error(), "retry") {
				t.Fatalf("error repeats the reply: %v", err)
			}
		})
	}
}

func TestA2ARefreshesAnExpiredTokenOnce(t *testing.T) {
	s := newRPC(t, func(n int) (int, string) {
		if n == 1 {
			return 401, "unauthorized"
		}
		return 200, okReply
	})
	var n atomic.Int32
	a := &A2A{BaseURL: s.URL, Token: tokenFn(&n, time.Hour)}
	if err := a.Send(context.Background(), Outgoing{Kind: "TASK"}); err != nil {
		t.Fatal(err)
	}
	if s.auth[0] != "Bearer tok1" || s.auth[1] != "Bearer tok2" {
		t.Fatalf("%v", s.auth)
	}
	// Still unauthorized after a fresh token: the answer is final.
	s2 := newRPC(t, func(int) (int, string) { return 401, "no" })
	a2 := &A2A{BaseURL: s2.URL, Token: tokenFn(&n, time.Hour)}
	if err := a2.Send(context.Background(), Outgoing{Kind: "TASK"}); !errors.Is(err, ErrGatewayFailed) || len(s2.calls) != 2 {
		t.Fatalf("%v calls=%d", err, len(s2.calls))
	}
}

func TestA2ATokenCacheHonoursExpiryAndErrors(t *testing.T) {
	s := newRPC(t, func(int) (int, string) { return 200, okReply })
	now := time.Unix(1_800_000_000, 0)
	var n atomic.Int32
	a := &A2A{BaseURL: s.URL, Token: func(ctx context.Context) (string, time.Time, error) {
		return fmt.Sprintf("t%d", n.Add(1)), now.Add(time.Minute), nil
	}, Now: func() time.Time { return now }}
	send := func() { t.Helper(); _ = a.Send(context.Background(), Outgoing{Kind: "TASK"}) }
	send()
	send()
	now = now.Add(45 * time.Second) // inside the slack before expiry
	send()
	if n.Load() != 2 {
		t.Fatalf("fetched %d tokens, want a renewal inside the last 30 seconds", n.Load())
	}
	for _, bad := range []func(context.Context) (string, time.Time, error){
		func(context.Context) (string, time.Time, error) { return "", time.Time{}, errors.New("no") },
		func(context.Context) (string, time.Time, error) { return "", now.Add(time.Hour), nil },
	} {
		a := &A2A{BaseURL: s.URL, Token: bad}
		if err := a.Send(context.Background(), Outgoing{Kind: "TASK"}); !errors.Is(err, ErrGatewayFailed) {
			t.Fatalf("%v", err)
		}
	}
}

func TestA2ANetworkFailureMeansNotDelivered(t *testing.T) {
	s := newRPC(t, func(int) (int, string) { return 200, okReply })
	url := s.URL
	s.Close()
	var n atomic.Int32
	a := &A2A{BaseURL: url, Token: tokenFn(&n, time.Hour), HTTP: &http.Client{Timeout: time.Second}}
	if err := a.Send(context.Background(), Outgoing{Kind: "TASK"}); !errors.Is(err, outbox.ErrOffline) || !errors.Is(err, ErrGatewayFailed) {
		t.Fatalf("%v", err)
	}
	if err := (&A2A{BaseURL: "http://bad host", Token: tokenFn(&n, time.Hour)}).Send(context.Background(), Outgoing{Kind: "TASK"}); !errors.Is(err, ErrGatewayFailed) {
		t.Fatalf("%v", err)
	}
}

// A redirect would carry the bearer token elsewhere: it is not followed.
func TestA2ADoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer other.Close()
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer gw.Close()
	var n atomic.Int32
	a := &A2A{BaseURL: gw.URL, Token: tokenFn(&n, time.Hour), HTTP: &http.Client{}}
	if err := a.Send(context.Background(), Outgoing{Kind: "TASK"}); err == nil || leaked.Load() {
		t.Fatalf("err=%v leaked=%v", err, leaked.Load())
	}
}

func TestA2ABoundsWhatItReads(t *testing.T) {
	s := newRPC(t, func(int) (int, string) { return 200, strings.Repeat("x", 1<<20) })
	var n atomic.Int32
	a := &A2A{BaseURL: s.URL, Token: tokenFn(&n, time.Hour)}
	if err := a.Send(context.Background(), Outgoing{Kind: "TASK"}); !errors.Is(err, ErrGatewayFailed) {
		t.Fatalf("%v", err)
	}
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		io.WriteString(w, "short") // the body ends before it promised
	}))
	defer s3.Close()
	if err := (&A2A{BaseURL: s3.URL, Token: tokenFn(&n, time.Hour)}).Send(context.Background(), Outgoing{Kind: "TASK"}); !errors.Is(err, ErrGatewayFailed) {
		t.Fatalf("%v", err)
	}
}
