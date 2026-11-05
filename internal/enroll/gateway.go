// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"net/http"
	"time"
)

const requestTimeout = 30 * time.Second

// newHTTP is the default client: a timeout, and no redirects at all. A gateway
// (or anything in front of it) that redirects is refused rather than followed,
// so credentials and requests never travel to another host. The URL scheme is
// checked by daemon.ValidGatewayURL: https, or http to loopback only.
func newHTTP() *http.Client {
	return &http.Client{Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
