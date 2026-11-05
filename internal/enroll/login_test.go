// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/logx"
)

func loginOpts(e *env) (LoginOptions, *[]string) {
	var shown []string
	return LoginOptions{
		Gateway: e.gw.srv.URL, Tenant: "acme", Sessions: &memSessions{}, Poll: time.Millisecond,
		Progress: func(s string) { shown = append(shown, s) },
	}, &shown
}

func TestLoginSignsInThroughTheBrowserAndKeepsTheSessionInTheStore(t *testing.T) {
	e := newEnv(t)
	e.gw.set(func(g *fakeGateway) { g.login.doneAfter = 2 })
	o, shown := loginOpts(e)
	var opened string
	o.Open = func(u string) error { opened = u; return nil }
	var logs bytes.Buffer
	o.Log = logx.New(&logs)
	sess := o.Sessions.(*memSessions)
	if err := Login(bg, o); err != nil {
		t.Fatal(err)
	}
	// The browser is sent to the gateway's own OIDC login for this tenant, as a user, for this device login.
	u, err := url.Parse(opened)
	if err != nil || u.Path != "/auth/google/login" || u.Query().Get("tenant") != "acme" || u.Query().Get("role") != "user" || u.Query().Get("device") != strings.Repeat("a", 32) {
		t.Fatalf("opened %q", opened)
	}
	text := strings.Join(*shown, "\n")
	if !strings.Contains(text, opened) || !strings.Contains(text, "ABCD-1234") {
		t.Errorf("the user must see the address and the code: %q", text)
	}
	// The stored token's secret is the one whose hash the gateway was given, and it is nowhere else.
	tok := sess.token["acme"]
	secret := strings.TrimPrefix(tok, "ps_acme.")
	if len(secret) != 64 || hexSHA(secret) != e.gw.loginSnap().sessionHash || e.gw.loginSnap().polls != 3 {
		t.Fatalf("token %q hash %q polls %d", tok, e.gw.loginSnap().sessionHash, e.gw.loginSnap().polls)
	}
	if strings.Contains(text, secret) || strings.Contains(logs.String(), secret) || strings.Contains(opened, secret) {
		t.Error("the session secret reached output")
	}
	if !strings.Contains(logs.String(), "signed in") {
		t.Errorf("logs %q", logs.String())
	}
}

func TestLoginFailures(t *testing.T) {
	t.Run("browser cannot be opened", func(t *testing.T) {
		e := newEnv(t)
		o, shown := loginOpts(e)
		o.Open = func(string) error { return errors.New("no browser") }
		if err := Login(bg, o); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(*shown, "\n"), "open the address above yourself") {
			t.Errorf("%q", *shown)
		}
	})
	t.Run("expired", func(t *testing.T) {
		e := newEnv(t)
		e.gw.set(func(g *fakeGateway) { g.login.notFound = true })
		o, _ := loginOpts(e)
		if err := Login(bg, o); !errors.Is(err, ErrLoginExpired) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("never confirmed", func(t *testing.T) {
		e := newEnv(t)
		e.gw.set(func(g *fakeGateway) { g.login.doneAfter = 1 << 30 })
		o, _ := loginOpts(e)
		o.Timeout = 30 * time.Millisecond
		sess := o.Sessions.(*memSessions)
		if err := Login(bg, o); !errors.Is(err, ErrLoginExpired) || sess.savedCount != 0 {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		e := newEnv(t)
		e.gw.set(func(g *fakeGateway) { g.login.doneAfter = 1 << 30 })
		o, _ := loginOpts(e)
		ctx, stop := context.WithCancel(bg)
		o.Poll = 5 * time.Second
		o.Open = func(string) error { time.AfterFunc(30*time.Millisecond, stop); return nil } // while it waits between polls
		if err := Login(ctx, o); !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("session cannot be stored", func(t *testing.T) {
		e := newEnv(t)
		o, _ := loginOpts(e)
		o.Sessions = &memSessions{saveErr: errors.New("keychain locked")}
		if err := Login(bg, o); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("gateway errors", func(t *testing.T) {
		for name, body := range map[string]func() (int, any){
			"server error": func() (int, any) { return 500, nil },
			"busy":         func() (int, any) { return 429, nil },
			"no id":        func() (int, any) { return 201, map[string]any{"code": "X"} },
			"no code":      func() (int, any) { return 201, map[string]any{"id": strings.Repeat("a", 32)} },
			"long code": func() (int, any) {
				return 201, map[string]any{"id": strings.Repeat("a", 32), "code": strings.Repeat("X", 17)}
			},
			"bad id": func() (int, any) { return 201, map[string]any{"id": "../x", "code": "X"} },
		} {
			e := newEnv(t)
			e.gw.set(func(g *fakeGateway) { g.login.startBody = body })
			o, _ := loginOpts(e)
			if err := Login(bg, o); err == nil || errors.Is(err, ErrLoginExpired) {
				t.Errorf("%s: %v (it must be refused at the start, not later)", name, err)
			}
			if e.gw.loginSnap().polls != 0 {
				t.Errorf("%s: the sign-in went on to poll", name)
			}
		}
		// The longest code allowed is accepted.
		e := newEnv(t)
		e.gw.set(func(g *fakeGateway) {
			g.login.startBody = func() (int, any) {
				return 201, map[string]any{"id": strings.Repeat("a", 32), "code": strings.Repeat("X", 16)}
			}
		})
		o, _ := loginOpts(e)
		if err := Login(bg, o); err != nil {
			t.Errorf("a 16 character code: %v", err)
		}
	})
	t.Run("poll fails", func(t *testing.T) {
		e := newEnv(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/login/poll" {
				w.WriteHeader(500)
				return
			}
			e.gw.serve(w, r)
		}))
		defer srv.Close()
		o, _ := loginOpts(e)
		o.Gateway = srv.URL
		if err := Login(bg, o); err == nil || errors.Is(err, ErrLoginExpired) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("input", func(t *testing.T) {
		for name, mod := range map[string]func(*LoginOptions){
			"http gateway": func(o *LoginOptions) { o.Gateway = "http://gw.example.test" },
			"tenant":       func(o *LoginOptions) { o.Tenant = "a b" },
			"provider":     func(o *LoginOptions) { o.Provider = "../x" },
			"entropy":      func(o *LoginOptions) { o.Rand = failRand{} },
			"poll entropy": func(o *LoginOptions) { n := 0; o.Rand = failAfter(&n, 1) },
		} {
			e := newEnv(t)
			o, _ := loginOpts(e)
			mod(&o)
			if err := Login(bg, o); err == nil {
				t.Errorf("%s: accepted", name)
			}
			if e.gw.loginSnap().starts != 0 {
				t.Errorf("%s: the gateway was contacted", name)
			}
		}
	})
	t.Run("defaults", func(t *testing.T) {
		e := newEnv(t)
		e.gw.set(func(g *fakeGateway) { g.login.doneAfter = 0 })
		o := LoginOptions{Gateway: e.gw.srv.URL, Tenant: "acme", Provider: "entra", Sessions: &memSessions{}}
		if err := Login(bg, o); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPostReportsStatusAndGarbage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/404":
			w.WriteHeader(404)
		case "/500":
			w.WriteHeader(500)
		case "/junk":
			w.Write([]byte("<html>"))
		default:
			w.Write([]byte(`{"state":"ok"}`))
		}
	}))
	defer srv.Close()
	var out struct{ State string }
	if err := post(bg, newHTTP(), srv.URL+"/", "/ok", map[string]string{}, &out); err != nil || out.State != "ok" {
		t.Fatalf("%v %+v", err, out)
	}
	if err := post(bg, newHTTP(), srv.URL, "/404", map[string]string{}, &out); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: %v", err)
	}
	for _, p := range []string{"/500", "/junk"} {
		if err := post(bg, newHTTP(), srv.URL, p, map[string]string{}, &out); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
	if err := post(bg, newHTTP(), "http://127.0.0.1:1", "/x", map[string]string{}, &out); err == nil {
		t.Error("a refused connection must fail")
	}
	if err := post(bg, newHTTP(), "http://a b", "/x", map[string]string{}, &out); err == nil {
		t.Error("a bad URL must fail")
	}
	srv.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("short"))
	}))
	defer broken.Close()
	if err := post(bg, newHTTP(), broken.URL, "/x", map[string]string{}, &out); err == nil {
		t.Error("a truncated body must fail")
	}
}

func TestWait(t *testing.T) {
	if err := wait(bg, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(bg)
	stop()
	if err := wait(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v", err)
	}
}

func TestLoginDoesNotFollowRedirects(t *testing.T) {
	var hit atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Add(1) }))
	defer elsewhere.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	err := Login(bg, LoginOptions{Gateway: redir.URL, Tenant: "acme", Sessions: &memSessions{}})
	if err == nil || hit.Load() != 0 {
		t.Fatalf("login followed a redirect: %v hits=%d", err, hit.Load())
	}
}

func TestOversizedGatewayRepliesAreRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte(" "), maxReply+1))
	}))
	defer srv.Close()
	err := post(bg, newHTTP(), srv.URL, "/x", map[string]string{}, &struct{}{})
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("got %v", err)
	}
}

func TestRequestEncodingFailureIsReported(t *testing.T) {
	boom := errors.New("cannot encode")
	defer func(old func(any) ([]byte, error)) { marshal = old }(marshal)
	marshal = func(any) ([]byte, error) { return nil, boom }
	if err := post(bg, newHTTP(), "http://127.0.0.1:1", "/x", map[string]string{}, &struct{}{}); !errors.Is(err, boom) {
		t.Errorf("request: %v", err)
	}
}

// The timeout can end the wait inside a poll request as well as between polls. Whichever it is, the answer is the
// same; a gateway that never answers the poll makes it the in-flight case every time (the stress run found the
// scheduling-dependent version of this: the raw "context deadline exceeded" was returned instead).
func TestLoginTimeoutWhileAPollIsInFlight(t *testing.T) {
	e := newEnv(t)
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/login/poll" {
			io.Copy(io.Discard, r.Body) // the server notices a closed connection only once the body is read
			<-r.Context().Done()        // never answers
			return
		}
		e.gw.serve(w, r)
	}))
	defer hung.Close()
	o, _ := loginOpts(e)
	o.Gateway = hung.URL
	o.Timeout = 50 * time.Millisecond
	sess := o.Sessions.(*memSessions)
	if err := Login(bg, o); !errors.Is(err, ErrLoginExpired) || sess.savedCount != 0 {
		t.Fatalf("got %v", err)
	}
	// The caller's own cancellation is not "expired": it is reported as what it is.
	ctx, stop := context.WithCancel(bg)
	time.AfterFunc(50*time.Millisecond, stop)
	o.Timeout = time.Minute
	if err := Login(ctx, o); !errors.Is(err, context.Canceled) || errors.Is(err, ErrLoginExpired) {
		t.Fatalf("got %v", err)
	}
	// And the caller's own deadline is not 'expired' either.
	dctx, stop2 := context.WithTimeout(bg, 50*time.Millisecond)
	defer stop2()
	if err := Login(dctx, o); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrLoginExpired) {
		t.Fatalf("got %v", err)
	}
}

func TestPollDefaultsAndBackoff(t *testing.T) {
	// A zero Poll means the default (2 s): a login that needs one more poll and has 300 ms runs out of time ...
	e := newEnv(t)
	e.gw.set(func(g *fakeGateway) { g.login.doneAfter = 1 })
	o, _ := loginOpts(e)
	o.Poll, o.Timeout = 0, 300*time.Millisecond
	if err := Login(bg, o); !errors.Is(err, ErrLoginExpired) {
		t.Fatalf("default poll: %v", err)
	}
	// ... while a short Poll that is given is used as given.
	e = newEnv(t)
	e.gw.set(func(g *fakeGateway) { g.login.doneAfter = 2 })
	o, _ = loginOpts(e)
	o.Poll, o.Timeout = time.Millisecond, 1500*time.Millisecond
	if err := Login(bg, o); err != nil {
		t.Fatalf("given poll: %v", err)
	}
	for in, want := range map[time.Duration]time.Duration{
		time.Millisecond: 1500 * time.Microsecond, 2 * time.Second: 3 * time.Second, 6 * time.Second: 9 * time.Second,
		7 * time.Second: maxLoginPoll, maxLoginPoll: maxLoginPoll,
	} {
		if got := nextPoll(in); got != want {
			t.Errorf("nextPoll(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestLimitsOfThePostHelperAreExact(t *testing.T) {
	if maxReply != 65536 || defaultLoginTimeout != 10*time.Minute || defaultPoll != 2*time.Second || maxLoginPoll != 10*time.Second {
		t.Errorf("limits changed: %d %v %v %v", maxReply, defaultLoginTimeout, defaultPoll, maxLoginPoll)
	}
	body := `{"state":"ok"}`
	for size, wantErr := range map[int]bool{maxReply: false, maxReply + 1: true} {
		reply := body + strings.Repeat(" ", size-len(body))
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(reply)) }))
		var out struct{ State string }
		err := post(bg, newHTTP(), srv.URL, "/x", map[string]string{}, &out)
		srv.Close()
		if (err != nil) != wantErr || (!wantErr && out.State != "ok") {
			t.Errorf("%d bytes: %v %+v", size, err, out)
		}
	}
	for code, wantErr := range map[int]bool{403: true, 200: false, 201: false, 299: false, 300: true, 404: true, 500: true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code); w.Write([]byte(`{}`)) }))
		err := post(bg, newHTTP(), srv.URL, "/x", map[string]string{}, &struct{}{})
		srv.Close()
		if (err != nil) != wantErr {
			t.Errorf("status %d: %v", code, err)
		}
	}
}

func TestJitterStaysWithinAQuarterAndVaries(t *testing.T) {
	d := 8 * time.Second
	seen := map[time.Duration]bool{}
	for range 2000 {
		j := jitter(d)
		if j < 6*time.Second || j > 10*time.Second {
			t.Fatalf("jitter(%v) = %v, outside 6s..10s", d, j)
		}
		seen[j] = true
	}
	if len(seen) < 100 {
		t.Errorf("only %d distinct values: no jitter", len(seen))
	}
	if j := jitter(time.Nanosecond); j < 0 || j > 2 {
		t.Errorf("tiny interval: %v", j)
	}
}
