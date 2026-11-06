// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"strings"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// The test bot is what `parley-cli test` talks to: it answers a task with the task text, prefixed, so a caller
// can prove the whole path (enrolled devices, prekey, sealed task, bot, sealed reply) with nothing but two
// daemons. It exists so that the path can be checked before any real bot is configured; it does nothing else.
//
//   - Only the owner of this device may use it: a caller whose root-signed binding names another owner is refused
//     at the prekey request, exactly like any other bot's allowlist (a second device of the same user, or a pod of
//     the same named service owner). A device never answers itself: the pipeline refuses a task from its own
//     device id (no reflection), so the test needs two devices.
//   - It runs inside the bot host (internal/bot): the same limits, timeouts and fixed error texts as a real bot.
//   - It is on unless Config.DisableTestBot is set, and it is replaced by Deps.Allow and Deps.OnInbound when a
//     caller of New supplies them (the real bots, T402).
const (
	// TestBotPrefix starts every answer of the test bot.
	TestBotPrefix = "parley echo: "
	// MaxTestTask is the longest task the test bot answers; a test needs a few dozen bytes.
	MaxTestTask = 1024
)

type echoBot struct{}

func (echoBot) Handle(_ context.Context, t bot.Task, _ bot.Session) ([]byte, error) {
	if len(t.Content) > MaxTestTask {
		return nil, &bot.Failure{Message: "the test task is too large"}
	}
	return append([]byte(TestBotPrefix), t.Content...), nil
}

// nodeResponder sends the bot host's messages through the pipeline, which exists only once the device is enrolled.
type nodeResponder struct{ d *Daemon }

func (r nodeResponder) Respond(ctx context.Context, id [16]byte, typ envelope.Type, content []byte) error {
	n, err := r.d.Node()
	if err != nil {
		return err
	}
	return n.Respond(ctx, id, typ, content)
}

// initTestBot makes the test bot the daemon's bot, unless it is disabled or a bot was supplied.
func (d *Daemon) initTestBot() {
	if d.cfg.DisableTestBot || d.deps.Allow != nil || d.deps.OnInbound != nil {
		return
	}
	// NewHost fails only without a bot or a responder, and both are given here.
	h, _ := bot.NewHost(bot.Config{Bot: echoBot{}, Responder: nodeResponder{d}, Now: d.deps.Now})
	d.host = h
	d.deps.OnInbound = h.Inbound
	d.deps.Allow = d.allowOwner
}

// allowOwner is the test bot's allowlist: the owner named by this device's own recorded binding.
func (d *Daemon) allowOwner(owner string) bool {
	mine, ok := d.tracker.Owner(d.cfg.Tenant, d.cfg.DeviceID)
	return ok && strings.EqualFold(owner, mine)
}

// Compile-time check: the host's inbound handler is what the pipeline calls.
var _ func(pipeline.Inbound) = (*bot.Host)(nil).Inbound
