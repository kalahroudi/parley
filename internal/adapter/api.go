// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kalahroudi/parley/internal/bot"
)

// ErrAPIConfig means the API adapter's URL or token is not acceptable.
var ErrAPIConfig = errors.New("adapter: invalid API configuration")

const cancelTimeout = 2 * time.Second

// APIConfig configures the API adapter.
type APIConfig struct {
	// URL is the bot service. https, or http only to a loopback address; no
	// credentials, query or fragment (a secret in a URL ends up in logs).
	URL string
	// Token, if set, is sent as a bearer token to URL and nowhere else. It is
	// read from the daemon's secret storage by the caller, never from a file in
	// the configuration directory.
	Token string
}

// API is a bot reached over HTTP.
type API struct {
	url    string
	token  string
	client *http.Client
}

// NewAPI validates cfg and returns the adapter.
func NewAPI(cfg APIConfig) (*API, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		strings.ContainsAny(cfg.Token, "\r\n\x00") {
		return nil, ErrAPIConfig
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return nil, ErrAPIConfig // the task and the token would cross the network in clear
		}
	default:
		return nil, ErrAPIConfig
	}
	return &API{url: u.String(), token: cfg.Token, client: &http.Client{
		Transport: &http.Transport{
			Proxy:              nil, // the plaintext task must not detour through an environment proxy
			TLSClientConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
			DisableCompression: true,
			DisableKeepAlives:  true, // one connection per task: no state a bot service keeps per connection spans callers
			ForceAttemptHTTP2:  true,
		},
		// A redirect would send the task, and the token, somewhere else: the 3xx is the answer, and it fails.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Handle implements bot.Bot.
func (a *API) Handle(ctx context.Context, t bot.Task, s bot.Session) ([]byte, error) {
	p := &apiPeer{a: a, id: t.ID}
	defer p.close()
	line := taskLine(t)
	p.scrub = append(p.scrub, line)
	if err := p.post(ctx, line); err != nil {
		return nil, err
	}
	return converse(ctx, p, s)
}

type apiPeer struct {
	a     *API
	id    [16]byte
	body  io.Closer
	r     *bufio.Reader
	final bool // the bot sent its result or error
	scrub [][]byte
}

func (p *apiPeer) post(ctx context.Context, line []byte) error {
	if p.body != nil {
		p.body.Close()
		p.body = nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.a.url, bytes.NewReader(line))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if p.a.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.a.token)
	}
	resp, err := p.a.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("adapter: the bot service is unreachable") // the transport's text names the URL: keep it out
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("adapter: the bot service answered %d", resp.StatusCode)
	}
	p.body, p.r = resp.Body, bufio.NewReaderSize(resp.Body, 64<<10)
	return nil
}

func (p *apiPeer) next() (message, error) {
	m, err := readMessage(p.r)
	if err == nil && (m.Type == typeResult || m.Type == typeError) {
		p.final = true
	}
	return m, err
}

func (p *apiPeer) answer(ctx context.Context, turn int, content []byte) error {
	line := answerLine(p.id, turn, content)
	p.scrub = append(p.scrub, line)
	return p.post(ctx, line)
}

// close ends the exchange. A task that ended without the bot's final message
// (canceled, expired, failed by the caller's side) is announced to the service,
// so one that holds state for a question the caller will never answer can drop it.
func (p *apiPeer) close() {
	if p.body != nil {
		p.body.Close()
	}
	if !p.final && p.r != nil { // nothing was started if the service never answered
		ctx, cancel := context.WithTimeout(context.Background(), cancelTimeout)
		defer cancel()
		line := cancelLine(p.id)
		p.scrub = append(p.scrub, line)
		if p.post(ctx, line) == nil {
			p.body.Close()
		}
	}
	for _, l := range p.scrub {
		clear(l)
	}
}
