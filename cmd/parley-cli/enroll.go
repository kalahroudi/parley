// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/enroll"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/update"
)

// tools are the parts of login and enroll that touch the outside world; tests replace them.
type tools struct {
	login    func(context.Context, enroll.LoginOptions) error
	enroll   func(context.Context, enroll.Options) (enroll.Result, error)
	sessions enroll.SessionStore
	open     func(string) error
	updater  func(pol daemon.UpdatePolicy, stateDir string) (*update.Updater, error)
}

func defaultTools() tools {
	return tools{login: enroll.Login, enroll: enroll.Enroll, sessions: enroll.KeyringSessions{KR: OSKeyring{}}, open: openBrowser, updater: defaultUpdater}
}

// openBrowser shows url in the system browser. The url is the gateway's login address built from validated parts.
//
//cover:ignore starts the system's browser; nothing to assert without one
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	}
	return exec.Command("xdg-open", url).Start()
}

// Secrets come from the environment, never from arguments: an argument is
// visible to every user of the machine in the process list and lands in the
// shell history.
const (
	envToken   = "PARLEY_ENROLL_TOKEN" // an admin-minted single-use pod enrollment token
	envGateway = "PARLEY_GATEWAY"
)

// login signs the user in through the gateway's OIDC flow in the system
// browser and keeps the session in the OS keychain.
func login(ctx context.Context, args []string, out, errw io.Writer, dirs daemon.Dirs, getenv func(string) string, t tools) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(errw)
	gateway := fs.String("gateway", getenv(envGateway), "gateway URL ($"+envGateway+")")
	tenant := fs.String("tenant", "", "tenant id")
	provider := fs.String("provider", "google", "identity provider the gateway offers (google, entra)")
	timeout := fs.Duration("timeout", 10*time.Minute, "how long to wait for the browser step")
	noBrowser := fs.Bool("no-browser", false, "only print the address; do not open the system browser")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	open := t.open
	if *noBrowser {
		open = nil
	}
	err := t.login(ctx, enroll.LoginOptions{
		Gateway: *gateway, Tenant: *tenant, Provider: *provider, Sessions: t.sessions, Open: open, Timeout: *timeout,
		Log: logx.New(errw), Progress: func(s string) { fmt.Fprintln(out, s) },
	})
	if err != nil {
		return report(errw, "login", err)
	}
	fmt.Fprintln(out, "Signed in. Next: parley-cli enroll -tenant", *tenant, "-root <fingerprint from your admin>")
	return 0
}

// enrollCmd creates the device key (once), requests approval, waits and stores the binding. With no
// arguments it continues an enrollment that was interrupted.
func enrollCmd(ctx context.Context, args []string, in io.Reader, out, errw io.Writer, dirs daemon.Dirs, getenv func(string) string, t tools) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(errw)
	gateway := fs.String("gateway", getenv(envGateway), "gateway URL ($"+envGateway+")")
	tenant := fs.String("tenant", "", "tenant id")
	rootFP := fs.String("root", "", "root fingerprint your admin shared (a channel other than Parley)")
	tofu := fs.Bool("trust-on-first-use", false, "no fingerprint at hand: show the root the gateway presents and ask you to confirm it")
	name := fs.String("name", "", "device name shown to the admin (default: the host name)")
	keyStore := fs.String("key-store", daemon.KeyStoreKeychain, "where the device key is kept: keychain, or file for headless hosts")
	useToken := fs.Bool("token", false, "enroll a pod with the single-use token in $"+envToken)
	replace := fs.Bool("replace", false, "the device key is lost: abandon this identity and start a new one")
	timeout := fs.Duration("timeout", time.Hour, "how long to wait for the admin")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	o := enroll.Options{
		Dirs: dirs, Gateway: *gateway, Tenant: *tenant, RootFingerprint: *rootFP, TrustOnFirstUse: *tofu, Name: *name, KeyStore: *keyStore,
		Sessions: t.sessions, Replace: *replace, Timeout: *timeout, Log: logx.New(errw), Progress: func(s string) { fmt.Fprintln(out, s) },
		Confirm: func(fp string) bool {
			fmt.Fprintf(out, "Type yes to trust the root with fingerprint %s: ", fp)
			line, _ := bufio.NewReader(in).ReadString('\n')
			return strings.EqualFold(strings.TrimSpace(line), "yes")
		},
	}
	if *useToken {
		if o.Token = getenv(envToken); o.Token == "" {
			fmt.Fprintf(errw, "error: -token needs the token in $%s\n", envToken)
			return 2
		}
		o.Sessions = nil
	}
	res, err := t.enroll(ctx, o)
	if err != nil {
		return report(errw, "enroll", err)
	}
	fmt.Fprintf(out, "Enrolled as device %s in tenant %s. Start parleyd to bring this device online.\n", res.Config.DeviceID, res.Config.Tenant)
	if len(res.Replaced) > 0 {
		fmt.Fprintf(out, "Ask your admin to revoke the replaced device(s): %s\n", strings.Join(res.Replaced, ", "))
	}
	return 0
}

// report prints an error for the operator: the cause, and what to do where there is a standard next step.
func report(errw io.Writer, cmd string, err error) int {
	switch {
	case errors.Is(err, context.Canceled):
		if cmd == "login" {
			fmt.Fprintln(errw, "interrupted: run parley-cli login again to sign in")
		} else {
			fmt.Fprintln(errw, "interrupted: run parley-cli enroll to continue where this stopped")
		}
	default:
		fmt.Fprintln(errw, "error:", err)
	}
	return 1
}
