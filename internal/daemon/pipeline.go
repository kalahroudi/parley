// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/kalahroudi/parley/internal/connect"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/frames"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/pipeline"
	"github.com/kalahroudi/parley/internal/prekey"
	"github.com/kalahroudi/parley/internal/receive"
	"github.com/kalahroudi/parley/internal/replay"
	"github.com/kalahroudi/parley/internal/tunnel"
)

// sweepEvery is the default for Deps.SweepEvery.
const sweepEvery = 5 * time.Second

// Node returns the daemon's message pipeline, building it on first use. It
// needs the device's own binding (the prekeys carry its version), so it fails
// with ErrNotEnrolled before enrollment. The pipeline's prekeys live in locked
// memory owned by the daemon process and are erased when Run returns.
func (d *Daemon) Node() (*pipeline.Node, error) {
	d.nodeMu.Lock()
	defer d.nodeMu.Unlock()
	if d.node != nil {
		return d.node, nil
	}
	version, ok := d.trust.Tracker.Version(d.cfg.Tenant, d.cfg.DeviceID)
	if !ok {
		return nil, ErrNotEnrolled
	}
	pub := d.signer.Public().(ed25519.PublicKey)
	pool, err := prekey.New(prekey.Config{Tenant: d.cfg.Tenant, DeviceID: d.cfg.DeviceID, SigningKeyID: pipeline.KeyID(pub),
		BindingVersion: version, Signer: d.signer, AllowUnlocked: d.deps.AllowUnlockedMemory, Now: d.deps.Now})
	if err != nil {
		return nil, err
	}
	directory, allow, inbound := d.deps.Directory, d.deps.Allow, d.deps.OnInbound
	if allow == nil || inbound == nil {
		// No bot runs here: nobody is allowed to start a task, so every prekey request is refused
		// rather than a task being accepted, erased and then dropped.
		allow, inbound = func(string) bool { return false }, func(pipeline.Inbound) {}
	}
	update := d.deps.OnUpdate
	if update == nil {
		update = func(pipeline.Update) {}
	}
	api := &connect.Client{BaseURL: d.cfg.GatewayURL, Tenant: d.cfg.Tenant, Device: d.cfg.DeviceID, HTTP: d.deps.HTTP}
	node, err := pipeline.New(pipeline.Config{
		Tenant: d.cfg.Tenant, Device: d.cfg.DeviceID, Signer: d.signer, Version: version,
		Pool: pool, Replay: replay.New(replay.Config{Now: d.deps.Now}), Trust: d.trust,
		Directory: directory, Allow: allow, Relay: d.relay,
		Gateway: &pipeline.A2A{BaseURL: d.cfg.GatewayURL, HTTP: d.deps.HTTP, Token: func(ctx context.Context) (string, time.Time, error) {
			tok, err := api.Token(ctx, d.signer, version, connect.ScopeAPI)
			return tok.Secret, tok.ExpiresAt, err
		}},
		OnInbound: inbound, OnUpdate: update, Now: d.deps.Now, Rand: d.deps.Rand,
	})
	if err != nil {
		pool.Close()
		return nil, err
	}
	d.node, d.pool = node, pool
	return node, nil
}

// relay puts a frame on the current tunnel; with none it fails, which the
// pipeline treats as "nothing was asked" and waits.
func (d *Daemon) relay(body string) error {
	c := d.tun.Load()
	if c == nil {
		return tunnel.ErrClosed
	}
	return c.Send(body)
}

// closeNode erases every key the pipeline holds. Called once, when Run ends.
func (d *Daemon) closeNode() {
	d.nodeMu.Lock()
	defer d.nodeMu.Unlock()
	if d.node != nil {
		d.node.Close()
		d.pool.Close()
		d.node, d.pool = nil, nil
	}
}

// handleEvent gives one tunnel event to the pipeline. A refused or dropped
// message is logged by class only: never the message, a key or an id of its peer.
func (d *Daemon) handleEvent(ctx context.Context, ev tunnel.Event) {
	d.deps.OnEvent(ev)
	node, err := d.Node()
	if err != nil {
		d.deps.Log.Warn("message dropped", logx.ID("type", "not_ready"))
		return
	}
	if f, dropped := dropField(node.HandleEvent(ctx, ev)); dropped {
		d.deps.Log.Warn("message dropped", f)
	}
}

// dropField names why a message was not processed, from a fixed set of literals (so nothing about the
// message can reach the log), and false when it was processed.
func dropField(err error) (logx.Field, bool) {
	switch {
	case err == nil:
		return logx.Field{}, false
	case errors.Is(err, receive.ErrDropped):
		return logx.ID("type", "dropped"), true
	case errors.Is(err, receive.ErrExpired):
		return logx.ID("type", "expired"), true
	case errors.Is(err, receive.ErrRejected), errors.Is(err, pipeline.ErrPeer):
		return logx.ID("type", "rejected"), true
	case errors.Is(err, frames.ErrFormat), errors.Is(err, frames.ErrUnsupported), errors.Is(err, envelope.ErrInvalid):
		return logx.ID("type", "format"), true
	}
	return logx.ID("type", "failed"), true
}

// runSweep ends tasks that ran out of time and erases their keys.
func (d *Daemon) runSweep(ctx context.Context) error {
	t := time.NewTicker(d.deps.SweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			d.nodeMu.Lock()
			n := d.node
			d.nodeMu.Unlock()
			if n != nil {
				n.Sweep()
			}
		}
	}
}
