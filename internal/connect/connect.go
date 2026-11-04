// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package connect is how a device gets into the gateway. The device proves it
// holds the signing key its root-signed binding names, and the gateway answers
// with a short-lived connect token (gateway/src/connect.ts is the other side):
//
//  1. POST /v1/connect/challenge {tenant, device} returns a random challenge
//     and its expiry. The gateway keeps only its hash, uses it once, and drops
//     it after a minute.
//  2. The device signs Message(tenant, device, challenge, expiry, binding
//     version, scope) with its Ed25519 key (the one in the daemon's keystore)
//     and POSTs /v1/connect/token with those and the signature. The gateway
//     checks that the device is bound at that version by a binding the tenant's
//     root signed, not revoked and not expired, verifies the signature, and
//     returns the token.
//
// A token with scope "connect" opens the tunnel once; one with scope "api"
// serves /a2a until it expires. Every refusal looks the
// same (ErrRefused). Nothing here logs or returns a challenge or a token
// inside an error, and a Token has no readable string form.
package connect

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const label = "parley/connect/v2"

// maxResponse bounds what is read from the gateway: a challenge or a token is a few hundred bytes.
const maxResponse = 16 << 10

// requestTimeout bounds one call when the caller supplies no HTTP client.
const requestTimeout = 30 * time.Second

var (
	// ErrRefused means the gateway would not issue a token: the device is not bound,
	// is revoked, its binding has expired, or the proof was not accepted.
	ErrRefused = errors.New("connect: the gateway refused this device")
	// ErrRateLimited means the gateway's per-device or per-address budget is spent; try again later, with backoff.
	ErrRateLimited = errors.New("connect: rate limited by the gateway")
	// ErrKey means the signing key is not an Ed25519 private key.
	ErrKey = errors.New("connect: invalid signing key")
	// ErrRequest means the version or scope asked for is not one the protocol has.
	ErrRequest = errors.New("connect: invalid token request")
	// ErrReply means the gateway's answer was not what the protocol allows.
	ErrReply = errors.New("connect: malformed reply from the gateway")
)

// Scope says what a token opens. It is part of what the device signs.
type Scope string

const (
	// ScopeConnect opens the tunnel (/v1/connect), once.
	ScopeConnect Scope = "connect"
	// ScopeAPI serves /a2a until the token expires.
	ScopeAPI Scope = "api"
)

// Message is what the device signs: the label and each text field,
// length-prefixed (4 bytes, big endian), with the challenge's expiry (unix
// milliseconds) and the binding version as 8-byte big-endian integers, so no
// field boundary is ambiguous and a signature cannot be moved to another
// challenge, expiry, binding version or scope.
func Message(tenant, device, challenge string, expiresAtMS int64, version uint64, scope Scope) []byte {
	var out []byte
	text := func(f string) {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	text(label)
	text(tenant)
	text(device)
	text(challenge)
	out = binary.BigEndian.AppendUint64(out, uint64(expiresAtMS))
	out = binary.BigEndian.AppendUint64(out, version)
	text(string(scope))
	return out
}

// Token is a device connect token. It is a credential: it has no readable
// string form, so it cannot reach a log by accident.
type Token struct {
	Secret    string
	ExpiresAt time.Time
}

func (Token) String() string   { return "connect.Token{redacted}" }
func (Token) GoString() string { return "connect.Token{redacted}" }

// Client asks one gateway for connect tokens for one device.
type Client struct {
	BaseURL string // the gateway's https URL (http only to loopback, enforced by the daemon's configuration)
	Tenant  string
	Device  string
	HTTP    *http.Client // nil uses a client with a timeout
}

// Token proves possession of signer's key for the device's binding at the
// given version and returns a fresh token of the given scope.
func (c *Client) Token(ctx context.Context, signer ed25519.PrivateKey, version uint64, scope Scope) (Token, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return Token{}, ErrKey
	}
	if version == 0 || (scope != ScopeConnect && scope != ScopeAPI) {
		return Token{}, ErrRequest
	}
	var ch struct {
		Challenge string `json:"challenge"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := c.post(ctx, "/v1/connect/challenge", map[string]string{"tenant": c.Tenant, "device": c.Device}, &ch); err != nil {
		return Token{}, err
	}
	if ch.Challenge == "" || ch.ExpiresAt <= 0 {
		return Token{}, ErrReply
	}
	sig := ed25519.Sign(signer, Message(c.Tenant, c.Device, ch.Challenge, ch.ExpiresAt, version, scope))
	var tok struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}
	err := c.post(ctx, "/v1/connect/token", map[string]any{"tenant": c.Tenant, "device": c.Device, "challenge": ch.Challenge, "version": version, "scope": scope, "signature": sig}, &tok)
	if err != nil {
		return Token{}, err
	}
	if tok.Token == "" || tok.ExpiresAt <= 0 {
		return Token{}, ErrReply
	}
	return Token{Secret: tok.Token, ExpiresAt: time.UnixMilli(tok.ExpiresAt)}, nil
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	body, _ := json.Marshal(in) // in is built above from strings and bytes only: it always marshals
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: requestTimeout}
	if c.HTTP != nil {
		copied := *c.HTTP
		hc = &copied
	}
	// A redirect would carry the signed proof to another host.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrRefused
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return ErrRateLimited
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("connect: gateway answered %d", resp.StatusCode)
	}
	if len(raw) > maxResponse {
		return ErrReply
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return ErrReply
	}
	return nil
}

// TunnelURL is the WebSocket URL of /v1/connect for a gateway's base URL:
// https becomes wss and http becomes ws.
func TunnelURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("connect: gateway URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("connect: gateway URL needs an http or https scheme")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/connect"
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}
