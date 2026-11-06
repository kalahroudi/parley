// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Command botd is the daemon the walking-skeleton acceptance test (tests/walking-skeleton.test.mjs) runs on the
// bot's machine. It is parleyd's daemon core (internal/daemon) with a real bot behind it: the CLI adapter running
// a program, inside the bot host, with the owner allowlist, and the bot's card published to the gateway. parleyd
// has no configuration for bots yet; this is the wiring that configuration will do, for tests only. It is never
// released and trusts nothing a release build would not.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/connect"
	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/envelope"
)

// responder sends the bot host's messages through the daemon's pipeline.
type responder struct{ d *daemon.Daemon }

func (r *responder) Respond(ctx context.Context, id [16]byte, typ envelope.Type, content []byte) error {
	n, err := r.d.Node()
	if err != nil {
		return err
	}
	return n.Respond(ctx, id, typ, content)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := serve(ctx, os.Args[1:], os.Getenv, os.Stderr)
	stop()
	os.Exit(code)
}

// serve runs the daemon until ctx ends and returns the process exit code.
func serve(ctx context.Context, args []string, getenv func(string) string, errw io.Writer) int {
	if err := run(ctx, args, getenv, errw); err != nil {
		//logx:allow fatal startup error for the test harness's terminal; no task content exists in this process path
		fmt.Fprintln(errw, "botd:", err)
		return 1
	}
	return 0
}

// allowOwner is the bot's allowlist: devices of this one owner.
func allowOwner(owner string) func(string) bool {
	return func(o string) bool { return strings.EqualFold(o, owner) }
}

func run(ctx context.Context, args []string, getenv func(string) string, logw io.Writer) error {
	fs := flag.NewFlagSet("botd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	owner := fs.String("owner", "", "the only owner whose devices may call the bot")
	command := fs.String("command", "", "absolute path of the bot program")
	name := fs.String("name", "walking-skeleton-bot", "the card's name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dirs, err := daemon.DefaultDirs(getenv, os.UserConfigDir)
	if err != nil {
		return err
	}
	cfg, err := daemon.LoadConfig(dirs.Config)
	if err != nil {
		return err
	}
	cli, err := adapter.NewCLI(adapter.CLIConfig{Command: *command, Args: fs.Args(), Env: []string{}})
	if err != nil {
		return err
	}
	resp := &responder{} // gets its daemon below, before anything runs
	host, err := bot.NewHost(bot.Config{Bot: cli, Responder: resp})
	if err != nil {
		return err
	}
	defer host.Close()
	d, err := daemon.New(cfg, dirs, daemon.Deps{
		Log:       daemon.NewLogger(logw, cfg.LogLevel),
		Allow:     allowOwner(*owner),
		OnInbound: host.Inbound,
	})
	if err != nil {
		return err
	}
	resp.d = d
	version := func() (uint64, bool) { return d.Trust().Tracker.Version(cfg.Tenant, cfg.DeviceID) }
	go publish(ctx, cfg, d.SigningKey(), version, *name)
	return d.Run(ctx)
}

// publish puts the bot's card in the tenant directory, retrying until the gateway accepts it.
func publish(ctx context.Context, cfg daemon.Config, signer ed25519.PrivateKey, binding func() (uint64, bool), name string) {
	card, _ := json.Marshal(map[string]any{"card": map[string]any{
		"name": name, "description": "Answers, asks one question, or waits, as its task says", "tags": []string{"skeleton"},
		"examples": []string{"echo your text"}, "visibility": "tenant",
	}})
	api := &connect.Client{BaseURL: cfg.GatewayURL, Tenant: cfg.Tenant, Device: cfg.DeviceID}
	for ctx.Err() == nil {
		if v, ok := binding(); ok {
			if tok, err := api.Token(ctx, signer, v, connect.ScopeAPI); err == nil {
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, cfg.GatewayURL+"/v1/cards/publish", bytes.NewReader(card))
				req.Header.Set("Authorization", "Bearer "+tok.Secret)
				req.Header.Set("Content-Type", "application/json")
				if res, err := http.DefaultClient.Do(req); err == nil {
					io.Copy(io.Discard, res.Body)
					res.Body.Close()
					if res.StatusCode == http.StatusOK {
						return
					}
				}
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
}
