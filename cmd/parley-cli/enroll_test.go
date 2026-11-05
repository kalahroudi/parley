// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/enroll"
)

type cli struct {
	t                   *testing.T
	home                string
	env                 map[string]string
	tl                  tools
	out                 bytes.Buffer
	errw                bytes.Buffer
	login               enroll.LoginOptions
	enroll              enroll.Options
	loginErr, enrollErr error
	res                 enroll.Result
	stdin               string
}

func newCLI(t *testing.T) *cli {
	c := &cli{t: t, home: t.TempDir(), env: map[string]string{}}
	c.tl = tools{
		login: func(_ context.Context, o enroll.LoginOptions) error {
			c.login = o
			o.Progress("open the page")
			return c.loginErr
		},
		enroll: func(_ context.Context, o enroll.Options) (enroll.Result, error) {
			c.enroll = o
			return c.res, c.enrollErr
		},
		sessions: enroll.KeyringSessions{},
		open:     func(string) error { return nil },
	}
	c.res = enroll.Result{Config: daemon.Config{DeviceID: "dev1", Tenant: "acme"}}
	return c
}

func (c *cli) run(args ...string) int {
	c.out.Reset()
	c.errw.Reset()
	return execute(context.Background(), args, strings.NewReader(c.stdin), &c.out, &c.errw, func() (string, error) { return c.home, nil }, func(k string) string { return c.env[k] }, c.tl)
}

func TestLoginPassesWhatItWasGiven(t *testing.T) {
	c := newCLI(t)
	c.env["PARLEY_GATEWAY"] = "https://gw.example.test"
	if code := c.run("login", "-tenant", "acme", "-provider", "entra", "-timeout", "3m"); code != 0 || c.errw.Len() != 0 && !strings.Contains(c.errw.String(), "") {
		t.Fatalf("%d %q", code, c.errw.String())
	}
	o := c.login
	if o.Gateway != "https://gw.example.test" || o.Tenant != "acme" || o.Provider != "entra" || o.Timeout != 3*time.Minute || o.Sessions == nil || o.Open == nil {
		t.Errorf("%+v", o)
	}
	if !strings.Contains(c.out.String(), "open the page") || !strings.Contains(c.out.String(), "Signed in") {
		t.Errorf("output %q", c.out.String())
	}
	c.run("login", "-tenant", "acme", "-no-browser")
	if c.login.Open != nil {
		t.Error("-no-browser must not open the browser")
	}
	// The gateway flag wins over the environment.
	c.run("login", "-gateway", "https://other.example.test", "-tenant", "acme")
	if c.login.Gateway != "https://other.example.test" {
		t.Errorf("gateway %q", c.login.Gateway)
	}
}

func TestEnrollPassesWhatItWasGivenAndAsksForTrustOnFirstUse(t *testing.T) {
	c := newCLI(t)
	c.env["PARLEY_HOME"] = filepath.Join(c.home, "h")
	c.env["PARLEY_GATEWAY"] = "https://gw.example.test"
	if code := c.run("enroll", "-tenant", "acme", "-root", "ABCD-EFGH", "-name", "laptop", "-key-store", "file", "-timeout", "5m", "-replace"); code != 0 {
		t.Fatalf("%d %q", code, c.errw.String())
	}
	o := c.enroll
	if o.Gateway != "https://gw.example.test" || o.Tenant != "acme" || o.RootFingerprint != "ABCD-EFGH" || o.Name != "laptop" || o.KeyStore != "file" || !o.Replace || o.Timeout != 5*time.Minute || o.Token != "" || o.Sessions == nil {
		t.Errorf("%+v", o)
	}
	if o.Dirs.State != c.env["PARLEY_HOME"] {
		t.Errorf("dirs %+v", o.Dirs)
	}
	if !strings.Contains(c.out.String(), "Enrolled as device dev1 in tenant acme") || strings.Contains(c.out.String(), "revoke") {
		t.Errorf("output %q", c.out.String())
	}
	// Trust on first use shows the fingerprint and needs a typed yes.
	for in, want := range map[string]bool{"yes\n": true, "YES\n": true, " yes \n": true, "y\n": false, "\n": false, "": false, "no\n": false} {
		c.stdin = in
		c.run("enroll", "-tenant", "acme", "-trust-on-first-use")
		if !c.enroll.TrustOnFirstUse {
			t.Fatal("flag lost")
		}
		if got := c.enroll.Confirm("AAAA-BBBB"); got != want {
			t.Errorf("%q: %v", in, got)
		}
	}
	if !strings.Contains(c.out.String(), "AAAA-BBBB") {
		t.Errorf("the prompt must show the fingerprint: %q", c.out.String())
	}
}

func TestEnrollWithNoArgumentsResumes(t *testing.T) {
	c := newCLI(t)
	c.res.Replaced = []string{"old1", "old2"}
	if code := c.run("enroll"); code != 0 {
		t.Fatal(code)
	}
	o := c.enroll
	if o.Gateway != "" || o.Tenant != "" || o.RootFingerprint != "" || o.TrustOnFirstUse || o.Replace {
		t.Errorf("a resume must carry no enrollment details: %+v", o)
	}
	if !strings.Contains(c.out.String(), "revoke the replaced device(s): old1, old2") {
		t.Errorf("output %q", c.out.String())
	}
}

func TestEnrollTokenComesFromTheEnvironmentOnly(t *testing.T) {
	c := newCLI(t)
	if code := c.run("enroll", "-token", "-tenant", "acme", "-root", "x"); code != 2 || !strings.Contains(c.errw.String(), "PARLEY_ENROLL_TOKEN") {
		t.Fatalf("%d %q", code, c.errw.String())
	}
	c.env["PARLEY_ENROLL_TOKEN"] = "pet_secret"
	if code := c.run("enroll", "-token", "-tenant", "acme", "-root", "x"); code != 0 {
		t.Fatalf("%d %q", code, c.errw.String())
	}
	if c.enroll.Token != "pet_secret" || c.enroll.Sessions != nil {
		t.Errorf("%+v", c.enroll)
	}
	if strings.Contains(c.out.String()+c.errw.String(), "pet_secret") {
		t.Error("the token was printed")
	}
	// Without -token the environment's token is not used: a pod says so.
	c.run("enroll", "-tenant", "acme", "-root", "x")
	if c.enroll.Token != "" {
		t.Error("token used without -token")
	}
}

func TestErrorsAreReportedForTheOperator(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"interrupted": {context.Canceled, "interrupted: run parley-cli %s"},
		"anything":    {errors.New("boom"), "error: boom"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newCLI(t)
			c.enrollErr, c.loginErr = tc.err, tc.err
			for _, args := range [][]string{{"enroll", "-tenant", "a", "-root", "x"}, {"login", "-tenant", "a"}} {
				c = newCLI(t)
				c.enrollErr, c.loginErr = tc.err, tc.err
				tc := tc
				if strings.Contains(tc.want, "%s") {
					tc.want = fmt.Sprintf(tc.want, args[0])
				}
				if code := c.run(args...); code != 1 || !strings.Contains(c.errw.String(), tc.want) || strings.Contains(c.out.String(), "Enrolled") || strings.Contains(c.out.String(), "Signed in") {
					t.Errorf("%v: %d %q", args, code, c.errw.String())
				}
			}
		})
	}
}

func TestBadArgumentsAndAMissingConfigDirectory(t *testing.T) {
	c := newCLI(t)
	c.tl.login = func(context.Context, enroll.LoginOptions) error { t.Error("must not run"); return nil }
	c.tl.enroll = func(context.Context, enroll.Options) (enroll.Result, error) {
		t.Error("must not run")
		return enroll.Result{}, nil
	}
	for _, args := range [][]string{{"login", "-bogus"}, {"login", "positional"}, {"enroll", "-bogus"}, {"enroll", "positional"}} {
		if code := c.run(args...); code != 2 {
			t.Errorf("%v: %d", args, code)
		}
	}
	var out, errw bytes.Buffer
	for _, cmd := range []string{"login", "enroll"} {
		errw.Reset()
		if code := execute(context.Background(), []string{cmd}, strings.NewReader(""), &out, &errw, func() (string, error) { return "", errors.New("no home") }, func(string) string { return "" }, c.tl); code != 1 || !strings.Contains(errw.String(), "no home") {
			t.Errorf("%s: %d %q", cmd, code, errw.String())
		}
	}
}

func TestDefaultToolsAreWired(t *testing.T) {
	d := defaultTools()
	if d.login == nil || d.enroll == nil || d.sessions == nil || d.open == nil {
		t.Errorf("%+v", d)
	}
}
