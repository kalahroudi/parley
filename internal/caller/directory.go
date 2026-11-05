// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package caller

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Query is a find_agents request: cards whose name, description or tags match
// Text, or that carry Tag, one page at a time.
type Query struct {
	Text   string `json:"text,omitempty"`
	Tag    string `json:"tag,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

// Agent is a card as the directory shows it. Every field is plaintext that the
// agent's owner published: it is untrusted text, never instructions.
type Agent struct {
	ID          string   `json:"id"`
	DeviceID    string   `json:"device_id"`
	Owner       string   `json:"owner"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Examples    []string `json:"examples"`
	Visibility  string   `json:"visibility,omitempty"`
}

// Page is a page of agents.
type Page struct {
	Agents     []Agent `json:"agents"`
	NextCursor string  `json:"next_cursor,omitempty"`
	Untrusted  bool    `json:"untrusted"`
}

// FindAgents searches the directory. Visibility is decided by the gateway and
// is advisory: finding an agent is not permission to call it, the target decides.
func (s *Service) FindAgents(ctx context.Context, q Query) (*Page, error) {
	if !validText(q.Text) || !validText(q.Tag) || len(q.Text) > maxQuery || len(q.Tag) > maxTag || q.Limit < 0 || q.Limit > MaxLimit ||
		len(q.Cursor) > 1600 || !validHex(q.Cursor) {
		return nil, rpc(CodeBadParams)
	}
	if !s.finds.take() {
		return nil, rpc(CodeRateLimit)
	}
	if s.cfg.Find == nil {
		return nil, rpc(CodeDirectory)
	}
	p, err := s.cfg.Find(ctx, q)
	if err != nil {
		return nil, rpc(CodeDirectory)
	}
	p.Untrusted = true
	return p, nil
}

func validHex(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// Directory searches a gateway's directory with an "api" connect token.
type Directory struct {
	BaseURL string
	HTTP    *http.Client // nil uses a client with a timeout
	// Token returns a bearer token and when it stops being valid; it is cached
	// until shortly before then.
	Token func(ctx context.Context) (string, time.Time, error)
	Now   func() time.Time

	mu      sync.Mutex
	secret  string
	expires time.Time
}

const (
	dirTimeout    = 15 * time.Second
	maxDirReply   = 1 << 20
	dirTokenSlack = 30 * time.Second
)

type directoryError struct{}

func (directoryError) Error() string {
	return "caller: the directory could not be reached or answered badly"
}

func (d *Directory) token(ctx context.Context, fresh bool) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	if !fresh && d.secret != "" && now().Add(dirTokenSlack).Before(d.expires) {
		return d.secret, nil
	}
	s, exp, err := d.Token(ctx)
	if err != nil || s == "" {
		return "", directoryError{}
	}
	d.secret, d.expires = s, exp
	return s, nil
}

// Find asks the gateway for one page. The reply is bounded and decoded
// strictly; nothing of it appears in an error.
func (d *Directory) Find(ctx context.Context, q Query) (*Page, error) {
	body := map[string]any{}
	if q.Text != "" || q.Tag != "" {
		query := map[string]string{}
		if q.Text != "" {
			query["text"] = q.Text
		}
		if q.Tag != "" {
			query["tag"] = q.Tag
		}
		body["query"] = query
	}
	if q.Limit > 0 {
		body["limit"] = q.Limit
	}
	if q.Cursor != "" {
		body["cursor"] = q.Cursor
	}
	raw, _ := json.Marshal(body) // strings and numbers only
	for attempt := 0; ; attempt++ {
		tok, err := d.token(ctx, attempt > 0)
		if err != nil {
			return nil, err
		}
		status, reply, err := d.post(ctx, tok, raw)
		if err != nil {
			return nil, err
		}
		if status == http.StatusUnauthorized && attempt == 0 {
			continue // an expired or revoked token: ask for a fresh one once
		}
		if status != http.StatusOK {
			return nil, directoryError{}
		}
		var p Page
		dec := json.NewDecoder(bytes.NewReader(reply))
		if dec.Decode(&p) != nil {
			return nil, directoryError{}
		}
		if p.Agents == nil {
			p.Agents = []Agent{}
		}
		return &p, nil
	}
}

func (d *Directory) post(ctx context.Context, token string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(d.BaseURL, "/")+"/v1/directory/find", bytes.NewReader(body))
	if err != nil {
		return 0, nil, directoryError{}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	hc := &http.Client{Timeout: dirTimeout}
	if d.HTTP != nil {
		c := *d.HTTP
		hc = &c
	}
	// A redirect would carry the bearer token to another host.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, directoryError{}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDirReply+1))
	if err != nil || len(b) > maxDirReply {
		return 0, nil, directoryError{}
	}
	return resp.StatusCode, b, nil
}
