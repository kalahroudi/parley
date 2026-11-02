// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/revocation"
	"github.com/kalahroudi/parley/internal/root"
)

// stub serves canned bodies by path; an unknown path answers 500.
func stub(t *testing.T, routes map[string]string) *Client {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.Error(w, "boom", 500)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL + "/", HTTP: srv.Client()}
}

func TestClientFailures(t *testing.T) {
	ctx := context.Background()
	c := stub(t, map[string]string{"/ok": `{}`, "/garbage": `not json`, "/v1/revocations": `[]`})
	if err := c.post(ctx, "/ok", make(chan int), nil); err == nil {
		t.Fatal("unmarshalable body")
	}
	if err := (&Client{BaseURL: "http://bad host"}).post(ctx, "/x", 1, nil); err == nil {
		t.Fatal("bad url")
	}
	if err := (&Client{BaseURL: "http://127.0.0.1:1"}).post(ctx, "/x", 1, nil); err == nil {
		t.Fatal("unreachable")
	}
	if err := c.post(ctx, "/boom", 1, nil); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("500: %v", err)
	}
	if err := c.post(ctx, "/garbage", 1, new(struct{})); err == nil {
		t.Fatal("bad json")
	}
	if err := c.post(ctx, "/ok", 1, nil); err != nil {
		t.Fatal(err)
	}

	// A body that ends early is a read error, not a half-decoded value.
	trunc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("{"))
	}))
	defer trunc.Close()
	if err := (&Client{BaseURL: trunc.URL}).post(ctx, "/x", 1, new(struct{})); err == nil {
		t.Fatal("truncated body")
	}

	// Every method passes its failure up.
	if _, _, err := c.RequestEnrollment(ctx, "n", nil); err == nil {
		t.Fatal("request")
	}
	if _, err := c.EnrollmentStatus(ctx, "t", "i", "p"); err == nil {
		t.Fatal("status")
	}
	if _, err := c.Pending(ctx); err == nil {
		t.Fatal("pending")
	}
	if _, err := c.FetchRevocations(ctx, "t"); err == nil {
		t.Fatal("fetch")
	}
	if err := c.Decide(ctx, "i", "approved"); err == nil {
		t.Fatal("decide")
	}
	if err := c.PostBinding(ctx, "i", &binding.Signed{}); err == nil {
		t.Fatal("binding")
	}
	if err := c.PostRevocations(ctx, &revocation.Signed{}); err == nil {
		t.Fatal("revocations")
	}
}

func TestEnrollFailures(t *testing.T) {
	r, _ := root.New()
	key := newKey(t)
	dev := func(c *Client) *Daemon {
		tr, _ := binding.NewTracker(r.Public, nil)
		return &Daemon{Tracker: tr, Client: c, Tenant: "t"}
	}
	clock := func() time.Time { return t0 }
	ctx := context.Background()

	if _, err := dev(stub(t, nil)).Enroll(ctx, "n", key, time.Millisecond, clock); err == nil {
		t.Fatal("request failure")
	}
	// The request goes through but the status poll fails.
	if _, err := dev(stub(t, map[string]string{"/v1/enroll/request": `{"id":"i","poll":"p"}`})).Enroll(ctx, "n", key, time.Millisecond, clock); err == nil {
		t.Fatal("status failure")
	}
	// Pending forever: the caller's context ends the wait.
	pending := stub(t, map[string]string{"/v1/enroll/request": `{"id":"i","poll":"p"}`, "/v1/enroll/status": `{"status":"pending"}`})
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, err := dev(pending).Enroll(cctx, "n", key, time.Millisecond, clock); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancel: %v", err)
	}

	// Approved with a binding that is not this device's, or not signed by the root.
	_, priv, _ := ed25519.GenerateKey(nil)
	mk := func(rootKey ed25519.PrivateKey, tenant, id string, k ed25519.PublicKey) *Client {
		s, err := binding.Sign(rootKey, binding.Binding{Tenant: tenant, Owner: "o", DeviceID: id, SigningKey: k, Version: 1, NotAfter: t0.Add(binding.Lifetime)})
		if err != nil {
			t.Fatal(err)
		}
		j, _ := jsonOf(map[string]any{"status": "approved", "binding": s})
		return stub(t, map[string]string{"/v1/enroll/request": `{"id":"i","poll":"p"}`, "/v1/enroll/status": j})
	}
	for name, c := range map[string]*Client{
		"other device": mk(priv, "t", "zzz", key),
		"other tenant": mk(priv, "x", "i", key),
		"other key":    mk(priv, "t", "i", newKey(t)),
	} {
		if _, err := dev(c).Enroll(ctx, "n", key, time.Millisecond, clock); !errors.Is(err, ErrWrongBinding) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := dev(mk(priv, "t", "i", key)).Enroll(ctx, "n", key, time.Millisecond, clock); !errors.Is(err, binding.ErrBadSignature) {
		t.Fatalf("not the pinned root: %v", err)
	}
	// Approved but the binding has not arrived yet: keep waiting, then accept it.
	var polls atomic.Int32
	good, _ := binding.Sign(r.Private, binding.Binding{Tenant: "t", Owner: "o", DeviceID: "i", SigningKey: key, Version: 1, NotAfter: t0.Add(binding.Lifetime)})
	gj, _ := jsonOf(map[string]any{"status": "approved", "binding": good})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/v1/enroll/request" {
			w.Write([]byte(`{"id":"i","poll":"p"}`))
		} else if polls.Add(1) < 3 {
			w.Write([]byte(`{"status":"approved"}`))
		} else {
			w.Write([]byte(gj))
		}
	}))
	defer srv.Close()
	if b, err := dev(&Client{BaseURL: srv.URL}).Enroll(ctx, "n", key, time.Millisecond, clock); err != nil || b.DeviceID != "i" || polls.Load() != 3 {
		t.Fatalf("late binding: %v", err)
	}
}

func TestAdminFailures(t *testing.T) {
	ctx := context.Background()
	r, _ := root.New()
	g, _ := revocation.NewGuard(r.Public, "t", nil, t0)
	dead := &Client{BaseURL: "http://127.0.0.1:1"}
	a := NewAdmin(r.Private, "t", dead, g)
	if err := a.Approve(ctx, Pending{ID: "i", Owner: "o", SigningKey: []byte{1}}, 1, t0); !errors.Is(err, binding.ErrInvalid) {
		t.Fatalf("bad key: %v", err)
	}
	if err := a.Approve(ctx, Pending{ID: "i", Owner: "o", SigningKey: newKey(t)}, 1, t0); err == nil {
		t.Fatal("decide failure")
	}
	if err := a.Reject(ctx, Pending{ID: "i"}); err == nil {
		t.Fatal("reject failure")
	}
	// A failed publish still advances the admin's own copy and reports the error; no renewal is claimed.
	if ok, err := a.RenewIfDue(ctx, t0); ok || err == nil {
		t.Fatalf("publish failure: %v %v", ok, err)
	}
	if g.Status(t0).Version != 1 {
		t.Fatal("own copy advances so the admin's own sends stay correct")
	}
}

func TestRunRefresh(t *testing.T) {
	r, _ := root.New()
	g, _ := revocation.NewGuard(r.Public, "t", nil, t0)
	d := &Daemon{Guard: g, Client: &Client{BaseURL: "http://127.0.0.1:1"}, Tenant: "t"}
	ctx, cancel := context.WithCancel(context.Background())
	var errs atomic.Int32
	done := make(chan struct{})
	go func() {
		d.RunRefresh(ctx, 5*time.Millisecond, func() time.Time { return t0 }, func(error) {
			if errs.Add(1) == 3 {
				cancel()
			}
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("RunRefresh did not stop")
	}
	if errs.Load() < 3 {
		t.Fatal("failures must be reported")
	}
	// After cancel, a failing refresh is not reported as an error.
	d.RunRefresh(ctx, time.Hour, func() time.Time { return t0 }, func(error) { t.Fatal("reported after cancel") })
}

func TestClientBoundsReplyAndTimeout(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"pad":"` + strings.Repeat("x", maxResponse) + `"}`))
	}))
	defer big.Close()
	if _, err := (&Client{BaseURL: big.URL}).EnrollmentStatus(context.Background(), "t", "i", "p"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize reply: %v", err)
	}
	if defaultHTTP.Timeout <= 0 {
		t.Fatal("default HTTP client has no timeout")
	}
}

func TestZeroIntervalsDoNotSpin(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/enroll/request" {
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"id":"i","poll":"p"}`))
			return
		}
		polls.Add(1)
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
	defer srv.Close()
	d := &Daemon{Client: &Client{BaseURL: srv.URL}, Tenant: "t"}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, _ = d.Enroll(ctx, "n", newKey(t), 0, func() time.Time { return t0 })
	if n := polls.Load(); n > 2 {
		t.Fatalf("zero poll interval spun: %d polls in 300ms", n)
	}
	// A zero refresh interval and a nil error callback must neither panic nor spin.
	g, _ := revocation.NewGuard(newKey(t), "t", nil, t0)
	d2 := &Daemon{Guard: g, Client: &Client{BaseURL: srv.URL}, Tenant: "t"}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	d2.RunRefresh(ctx2, 0, func() time.Time { return t0 }, nil)
	if n := polls.Load(); n > 4 {
		t.Fatalf("zero refresh interval spun: %d requests", n)
	}
}
