// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kalahroudi/parley/internal/frames"
	"github.com/kalahroudi/parley/internal/outbox"
)

// Gateway errors. The text is fixed: nothing the gateway says is repeated.
var (
	ErrGatewayRefused  = errors.New("pipeline: the gateway refused the message")
	ErrGatewayFailed   = errors.New("pipeline: the gateway could not be reached or answered badly")
	ErrNotPermitted    = errors.New("pipeline: not permitted to send to this target")
	ErrGatewayTooLarge = errors.New("pipeline: message too large for the gateway")
)

// RateLimited is returned when the gateway's limiter refuses a message; the
// outbox waits out RetryAfter.
type RateLimited struct{ After time.Duration }

func (e *RateLimited) Error() string             { return "pipeline: rate limited by the gateway" }
func (e *RateLimited) RetryAfter() time.Duration { return e.After }
func (e *RateLimited) Unwrap() error             { return outbox.ErrOffline }

// A2A is the Gateway over the gateway's A2A endpoint (POST /a2a, JSON-RPC).
type A2A struct {
	BaseURL string
	HTTP    *http.Client // nil uses a client with a timeout
	// Token returns a bearer token for /a2a (an "api" connect token) and when it
	// stops being valid. It is cached until shortly before then.
	Token func(ctx context.Context) (secret string, expires time.Time, err error)
	Now   func() time.Time // nil means time.Now

	mu      sync.Mutex
	secret  string
	expires time.Time
}

const (
	a2aTimeout     = 30 * time.Second
	maxReplyBytes  = 64 << 10
	tokenSlack     = 30 * time.Second
	errOffline     = -32010
	errRateLimited = -32016
	errForbidden   = -32013
	errTooLarge    = -32014
)

func (a *A2A) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *A2A) token(ctx context.Context, fresh bool) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !fresh && a.secret != "" && a.now().Add(tokenSlack).Before(a.expires) {
		return a.secret, nil
	}
	s, exp, err := a.Token(ctx)
	if err != nil || s == "" {
		return "", ErrGatewayFailed
	}
	a.secret, a.expires = s, exp
	return s, nil
}

func messageID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand does not fail on supported platforms
	return hex.EncodeToString(b[:])
}

// Send is SendMessage with one sealed part.
func (a *A2A) Send(ctx context.Context, m Outgoing) error {
	role := "ROLE_AGENT"
	if m.Kind == "TASK" || m.Kind == "REPLY" {
		role = "ROLE_USER"
	}
	return a.call(ctx, "SendMessage", map[string]any{"message": map[string]any{
		"messageId": messageID(), "role": role,
		"parts":    []map[string]string{{"raw": base64.StdEncoding.EncodeToString(m.Wire), "mediaType": frames.SealedMediaType}},
		"metadata": map[string]any{"parley": map[string]any{"kind": m.Kind, "to": m.Target, "seq": m.Seq}},
	}})
}

// Cancel is CancelTask carrying the signed CANCEL envelope.
func (a *A2A) Cancel(ctx context.Context, m Outgoing) error {
	return a.call(ctx, "CancelTask", map[string]any{"id": m.Task, "metadata": map[string]any{"parley": map[string]any{
		"messageId": messageID(), "seq": m.Seq,
		"parts": []map[string]string{{"raw": base64.StdEncoding.EncodeToString(m.Wire), "mediaType": frames.SealedMediaType}},
	}}})
}

func (a *A2A) call(ctx context.Context, method string, params map[string]any) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": messageID(), "method": method, "params": params}) // built from strings and numbers
	for attempt := 0; ; attempt++ {
		tok, err := a.token(ctx, attempt > 0)
		if err != nil {
			return err
		}
		status, reply, err := a.post(ctx, tok, body)
		if err != nil {
			return err
		}
		if status == http.StatusUnauthorized && attempt == 0 {
			continue // an expired or revoked token: ask for a fresh one once
		}
		return classify(status, reply)
	}
}

func (a *A2A) post(ctx context.Context, token string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.BaseURL, "/")+"/a2a", bytes.NewReader(body))
	if err != nil {
		return 0, nil, ErrGatewayFailed
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	hc := &http.Client{Timeout: a2aTimeout}
	if a.HTTP != nil {
		c := *a.HTTP
		hc = &c
	}
	// A redirect would carry the bearer token to another host.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		// The request may not have reached the gateway: for a task that is the
		// same as "recipient offline" (nothing delivered), so the outbox retries.
		return 0, nil, fmt.Errorf("%w: %w", outbox.ErrOffline, ErrGatewayFailed)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes))
	if err != nil {
		return 0, nil, ErrGatewayFailed
	}
	return resp.StatusCode, b, nil
}

// classify turns a JSON-RPC reply into an error from a fixed set.
func classify(status int, reply []byte) error {
	var r struct {
		Error *struct {
			Code int `json:"code"`
			Data struct {
				RetryAfterMS int64 `json:"retry_after_ms"`
			} `json:"data"`
		} `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(reply, &r) != nil {
		return ErrGatewayFailed
	}
	if r.Error != nil {
		switch r.Error.Code {
		case errOffline:
			return fmt.Errorf("%w: %w", outbox.ErrOffline, ErrGatewayRefused)
		case errRateLimited:
			return &RateLimited{After: time.Duration(max(r.Error.Data.RetryAfterMS, 0)) * time.Millisecond}
		case errForbidden:
			return ErrNotPermitted
		case errTooLarge:
			return ErrGatewayTooLarge
		}
		return ErrGatewayRefused
	}
	if status != http.StatusOK || len(r.Result) == 0 {
		return ErrGatewayFailed
	}
	return nil
}
