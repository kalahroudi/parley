// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"net/http"
	"net/url"
	"os"
	"testing"
)

// authFor returns the Authorization header for a user or admin of a tenant. The
// in-process fake accepts a made-up bearer; the real gateway has no such
// shortcut, so the test signs in through its OIDC login (against the mock IdP
// the Node harness started), as a person would, and uses the session token.
func authFor(t *testing.T, gateway, tenant, role, email string) string {
	t.Helper()
	if os.Getenv("PARLEY_TEST_GATEWAY_HTTP") == "" {
		return "Bearer fake-" + role + ":" + tenant + ":" + email
	}
	hop := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	jar := map[string]string{}
	do := func(u string, useJar bool) *http.Response {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			t.Fatal(err)
		}
		if useJar {
			for k, v := range jar {
				req.AddCookie(&http.Cookie{Name: k, Value: v})
			}
		}
		res, err := hop.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		for _, c := range res.Cookies() {
			jar[c.Name] = c.Value
		}
		return res
	}
	q := url.Values{"tenant": {tenant}, "role": {role}, "login_hint": {email}}
	res := do(gateway+"/auth/google/login?"+q.Encode(), false)
	res = do(res.Header.Get("Location"), false) // the mock IdP approves at once
	back, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, gateway+back.RequestURI(), nil)
	for k, v := range jar {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	res2, err := hop.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	for _, c := range res2.Cookies() {
		if c.Name == "parley_session" && c.Value != "" {
			return "Bearer " + c.Value
		}
	}
	t.Fatalf("no session for %s %s (status %d)", role, email, res2.StatusCode)
	return ""
}
