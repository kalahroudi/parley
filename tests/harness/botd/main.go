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

//cover:ignore test harness, run as a process by tests/walking-skeleton.test.mjs, which is its test
func (r *responder) Respond(ctx context.Context, id [16]byte, typ envelope.Type, content []byte) error {
	n, err := r.d.Node()
	if err != nil {
		return err
	}
	return n.Respond(ctx, id, typ, content)
}

//cover:ignore test harness, run as a process by tests/walking-skeleton.test.mjs, which is its test
func main() {
	if err := run(); err != nil {
		//logx:allow fatal startup error for the test harness's terminal; no task content exists in this process path
		fmt.Fprintln(os.Stderr, "botd:", err)
		os.Exit(1)
	}
}

//cover:ignore test harness, run as a process by tests/walking-skeleton.test.mjs, which is its test
func run() error {
	owner := flag.String("owner", "", "the only owner whose devices may call the bot")
	command := flag.String("command", "", "absolute path of the bot program")
	name := flag.String("name", "walking-skeleton-bot", "the card's name")
	flag.Parse()

	dirs, err := daemon.DefaultDirs(os.Getenv, os.UserConfigDir)
	if err != nil {
		return err
	}
	cfg, err := daemon.LoadConfig(dirs.Config)
	if err != nil {
		return err
	}
	cli, err := adapter.NewCLI(adapter.CLIConfig{Command: *command, Args: flag.Args(), Env: []string{}})
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
		Log:       daemon.NewLogger(os.Stderr, cfg.LogLevel),
		Allow:     func(o string) bool { return strings.EqualFold(o, *owner) },
		OnInbound: host.Inbound,
	})
	if err != nil {
		return err
	}
	resp.d = d
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go publish(ctx, d, cfg, *name)
	return d.Run(ctx)
}

// publish puts the bot's card in the tenant directory, retrying until the gateway accepts it.
//
//cover:ignore test harness, run as a process by tests/walking-skeleton.test.mjs, which is its test
func publish(ctx context.Context, d *daemon.Daemon, cfg daemon.Config, name string) {
	card, _ := json.Marshal(map[string]any{"card": map[string]any{
		"name": name, "description": "Answers, asks one question, or waits, as its task says", "tags": []string{"skeleton"},
		"examples": []string{"echo your text"}, "visibility": "tenant",
	}})
	api := &connect.Client{BaseURL: cfg.GatewayURL, Tenant: cfg.Tenant, Device: cfg.DeviceID}
	for ctx.Err() == nil {
		if v, ok := d.Trust().Tracker.Version(cfg.Tenant, cfg.DeviceID); ok {
			if tok, err := api.Token(ctx, d.SigningKey(), v, connect.ScopeAPI); err == nil {
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
