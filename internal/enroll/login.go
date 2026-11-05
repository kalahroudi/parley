// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/logx"
)

// maxReply bounds what is read from the gateway.
const maxReply = 64 << 10

// ErrNotFound is a 404 from the gateway (an unknown or expired login).
var ErrNotFound = errors.New("enroll: not found at the gateway")

// ErrLoginExpired means the browser step was not completed in time.
var ErrLoginExpired = errors.New("enroll: the sign-in was not confirmed in time; run parley-cli login again")

const (
	defaultLoginTimeout = 10 * time.Minute
	maxLoginPoll        = 10 * time.Second
)

var providerRe = regexp.MustCompile(`^[a-z]{1,20}$`)

// LoginOptions are the inputs of Login.
type LoginOptions struct {
	Gateway, Tenant string
	Provider        string // identity provider name at the gateway; default "google"
	Sessions        SessionStore
	// Open shows the sign-in URL in the system browser. It may be nil or fail: the
	// URL is always printed too.
	Open     func(url string) error
	Poll     time.Duration
	Timeout  time.Duration
	HTTP     *http.Client
	Rand     io.Reader
	Log      *logx.Logger
	Progress func(string)
}

func hexSHA(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// Login signs the user in through the gateway's OIDC flow and keeps the session
// in the OS keychain. The CLI makes the session secret and a poll secret and
// sends the gateway only their hashes; the browser step (system browser, the
// gateway's own OIDC with state, nonce and PKCE) ends with the user confirming
// the code this terminal shows; the CLI never sees an IdP secret and the
// gateway never holds a usable session secret. The session is not printed or
// logged and is never written to a file.
func Login(ctx context.Context, o LoginOptions) error {
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	if o.HTTP == nil {
		o.HTTP = newHTTP()
	}
	if o.Progress == nil {
		o.Progress = func(string) {}
	}
	if o.Log == nil {
		o.Log = logx.New(io.Discard)
	}
	if o.Provider == "" {
		o.Provider = "google"
	}
	if o.Poll <= 0 {
		o.Poll = defaultPoll
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultLoginTimeout
	}
	gw := strings.TrimRight(o.Gateway, "/")
	if err := daemon.ValidGatewayURL(gw); err != nil {
		return err
	}
	if !daemon.ValidID(o.Tenant) || !providerRe.MatchString(o.Provider) {
		return fmt.Errorf("%w: a tenant id and a provider name (letters) are required", daemon.ErrConfig)
	}
	secret, err := randHex(o.Rand, 32)
	if err != nil {
		return err
	}
	pollSecret, err := randHex(o.Rand, 32)
	if err != nil {
		return err
	}
	var st struct {
		ID, Code  string
		ExpiresAt int64 `json:"expires_at"`
	}
	if err := post(ctx, o.HTTP, gw, "/v1/login/start", map[string]string{"tenant": o.Tenant, "session_hash": hexSHA(secret), "poll_hash": hexSHA(pollSecret)}, &st); err != nil {
		return err
	}
	if !idRe.MatchString(st.ID) || st.Code == "" || len(st.Code) > 16 {
		return errors.New("enroll: the gateway's sign-in reply is not valid")
	}
	q := url.Values{"tenant": {o.Tenant}, "role": {"user"}, "device": {st.ID}}
	link := gw + "/auth/" + o.Provider + "/login?" + q.Encode()
	o.Progress("Sign in in your browser: " + link)
	o.Progress("The page will show the code " + st.Code + ". Confirm it only if it matches.")
	if o.Open != nil {
		if o.Open(link) != nil {
			o.Progress("(the browser could not be opened; open the address above yourself)")
		}
	}
	o.Log.Info("sign-in started", logx.ID("tenant", o.Tenant))

	// Our own timeout ending the wait is "not confirmed in time" wherever it lands: between polls or inside one.
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	timedOut := func(err error) bool { return errors.Is(err, context.DeadlineExceeded) && parent.Err() == nil }
	poll := o.Poll
	for {
		var r struct{ State string }
		err := post(ctx, o.HTTP, gw, "/v1/login/poll", map[string]string{"tenant": o.Tenant, "id": st.ID, "poll": pollSecret}, &r)
		switch {
		case errors.Is(err, ErrNotFound), timedOut(err):
			return ErrLoginExpired
		case err != nil:
			return err
		case r.State == "done":
			if err := o.Sessions.Save(o.Tenant, "ps_"+o.Tenant+"."+secret); err != nil {
				return err
			}
			o.Log.Info("signed in", logx.ID("tenant", o.Tenant))
			return nil
		}
		if err := wait(ctx, poll); err != nil {
			if timedOut(err) {
				return ErrLoginExpired
			}
			return err
		}
		poll = min(poll+poll/2, maxLoginPoll)
	}
}

// post sends a JSON body and decodes a bounded JSON reply into out.
func post(ctx context.Context, hc *http.Client, base, path string, in, out any) error {
	body, err := marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReply+1))
	if err != nil {
		return err
	}
	if len(raw) > maxReply {
		return errors.New("enroll: gateway reply too large")
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode/100 != 2:
		return fmt.Errorf("enroll: gateway answered %d for %s", resp.StatusCode, path)
	}
	return json.Unmarshal(raw, out)
}

// wait sleeps for d or until ctx ends.
func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
