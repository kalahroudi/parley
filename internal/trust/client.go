// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package trust wires the root-signed bindings (internal/binding) and the
// signed revocation list (internal/revocation) to the gateway and to the
// daemon's send path. The gateway only relays signed statements; everything
// received from it is verified against the pinned root before it is used.
package trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/revocation"
)

// maxResponse bounds what is read from the gateway.
const maxResponse = 1 << 20

// ErrTooLarge means the gateway's reply exceeded maxResponse.
var ErrTooLarge = errors.New("trust: gateway reply too large")

// requestTimeout bounds one call when the caller supplies no HTTP client.
const requestTimeout = 30 * time.Second

// defaultHTTP has a timeout, unlike http.DefaultClient, so a stalled gateway
// cannot hang the daemon.
var defaultHTTP = &http.Client{Timeout: requestTimeout}

// ErrNotFound is returned when the gateway has no such record (HTTP 404).
var ErrNotFound = errors.New("trust: not found at the gateway")

// Client talks to the gateway's enrollment and trust routes. Auth is the
// Authorization header value for routes that need an identity; the gateway's
// session handling decides what is accepted, this client does not interpret it.
type Client struct {
	BaseURL string
	Auth    string
	HTTP    *http.Client
}

// Pending is an enrollment request as the admin sees it.
type Pending struct {
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	SigningKey  []byte `json:"signing_key"`
	Fingerprint string `json:"fingerprint"`
}

// Status is the device's view of its enrollment request.
type Status struct {
	Status      string          `json:"status"`
	Fingerprint string          `json:"fingerprint"`
	Binding     *binding.Signed `json:"binding"`
}

// post sends a JSON body and decodes a JSON reply into out (if non-nil).
func (c *Client) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Auth != "" {
		req.Header.Set("Authorization", c.Auth)
	}
	h := c.HTTP
	if h == nil {
		h = defaultHTTP
	}
	resp, err := h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if len(raw) > maxResponse {
		return ErrTooLarge
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode/100 != 2:
		return fmt.Errorf("trust: gateway answered %d for %s", resp.StatusCode, path)
	case out == nil:
		return nil
	}
	return json.Unmarshal(raw, out)
}

// RequestEnrollment asks for approval of a device key. Needs a user identity.
// It returns the request id and the secret for polling its status.
func (c *Client) RequestEnrollment(ctx context.Context, name string, key ed25519.PublicKey) (id, poll string, err error) {
	var r struct{ ID, Poll string }
	err = c.post(ctx, "/v1/enroll/request", map[string]any{"name": name, "signing_key": key}, &r)
	return r.ID, r.Poll, err
}

// EnrollmentStatus polls a request with the secret from RequestEnrollment.
func (c *Client) EnrollmentStatus(ctx context.Context, tenant, id, poll string) (*Status, error) {
	var s Status
	if err := c.post(ctx, "/v1/enroll/status", map[string]string{"tenant": tenant, "id": id, "poll": poll}, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Pending lists requests awaiting a decision. Needs an admin identity.
func (c *Client) Pending(ctx context.Context) ([]Pending, error) {
	var r struct{ Pending []Pending }
	err := c.post(ctx, "/v1/admin/enrollments", struct{}{}, &r)
	return r.Pending, err
}

// Decide records the admin's decision at the gateway ("approved" or "rejected").
func (c *Client) Decide(ctx context.Context, id, decision string) error {
	return c.post(ctx, "/v1/admin/enrollments/decide", map[string]string{"id": id, "decision": decision}, nil)
}

// PostBinding hands the root-signed binding for an approved request to the gateway.
func (c *Client) PostBinding(ctx context.Context, id string, b *binding.Signed) error {
	return c.post(ctx, "/v1/admin/bindings", map[string]any{"id": id, "binding": b}, nil)
}

// PostRevocations publishes the root-signed revocation list. It is the Push
// function of a revocation.Renewer.
func (c *Client) PostRevocations(ctx context.Context, l *revocation.Signed) error {
	return c.post(ctx, "/v1/admin/revocations", map[string]any{"list": l}, nil)
}

// FetchRevocations reads the newest list the gateway holds, for revocation.Guard.Refresh.
func (c *Client) FetchRevocations(ctx context.Context, tenant string) (*revocation.Signed, error) {
	var l revocation.Signed
	if err := c.post(ctx, "/v1/revocations", map[string]string{"tenant": tenant}, &l); err != nil {
		return nil, err
	}
	return &l, nil
}
