// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// fetchTimeout bounds one download (the binaries are tens of megabytes).
const fetchTimeout = 10 * time.Minute

// DefaultSource is where the project publishes releases.
const DefaultSource = "https://github.com/kalahroudi/parley/releases"

// Source fetches release assets. It is untrusted: everything it returns is verified by the caller.
type Source interface {
	// Fetch writes the named asset of a release to w, failing when it is larger than limit bytes. An empty
	// version means the latest release.
	Fetch(ctx context.Context, version, name string, limit int64, w io.Writer) error
}

// ErrSource means a release source address is not acceptable.
var ErrSource = errors.New("update: release source must be an https address (http only to a loopback host)")

// ValidSource accepts https, or http to a loopback host (tests, local mirrors), with no credentials, query or
// fragment, so the address can be logged and joined with asset names safely.
func ValidSource(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !allowedURL(u) {
		return ErrSource
	}
	return nil
}

func allowedURL(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
}

// HTTPSource downloads from a GitHub-style release address: <Base>/latest/download/<name> and
// <Base>/download/<version>/<name>.
type HTTPSource struct {
	Base   string
	Client *http.Client // nil: a client with a 10 minute timeout
}

// Fetch implements Source. Every redirect must also be https (or loopback http).
func (s HTTPSource) Fetch(ctx context.Context, version, name string, limit int64, w io.Writer) error {
	if err := ValidSource(s.Base); err != nil {
		return err
	}
	loc := strings.TrimRight(s.Base, "/") + "/latest/download/" + name
	if version != "" {
		loc = strings.TrimRight(s.Base, "/") + "/download/" + version + "/" + name
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
	if err != nil {
		return err
	}
	c := http.Client{Timeout: fetchTimeout}
	if s.Client != nil {
		c = *s.Client
	}
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		// A redirect may never lower the transport: from https it must stay https (a loopback http mirror
		// may redirect within http).
		if len(via) >= 5 || !allowedURL(r.URL) || (via[0].URL.Scheme == "https" && r.URL.Scheme != "https") {
			return ErrSource
		}
		return nil
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update: %s: HTTP %d", name, resp.StatusCode)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("update: %s is larger than %d bytes", name, limit)
	}
	return nil
}
