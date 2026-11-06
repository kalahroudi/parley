// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"time"

	"github.com/kalahroudi/parley/internal/caller"
	"github.com/kalahroudi/parley/internal/connect"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// initCaller registers the caller interface on the local socket: find_agents,
// send_task, get_task, cancel_task and list_tasks (internal/caller). The
// pipeline's updates about tasks this device sent go to it first, then on to
// Deps.OnUpdate. Methods registered with Handle afterwards may replace these.
func (d *Daemon) initCaller() {
	api := &connect.Client{BaseURL: d.cfg.GatewayURL, Tenant: d.cfg.Tenant, Device: d.cfg.DeviceID, HTTP: d.deps.HTTP}
	dir := &caller.Directory{BaseURL: d.cfg.GatewayURL, HTTP: d.deps.HTTP, Now: d.deps.Now,
		Token: func(ctx context.Context) (string, time.Time, error) {
			v, ok := d.tracker.Version(d.cfg.Tenant, d.cfg.DeviceID)
			if !ok {
				return "", time.Time{}, ErrNotEnrolled
			}
			tok, err := api.Token(ctx, d.signer, v, connect.ScopeAPI)
			return tok.Secret, tok.ExpiresAt, err
		}}
	if d.deps.Directory == nil {
		d.deps.Directory = dir.Binding
	}
	d.caller = caller.New(caller.Config{
		Node: func() (caller.Node, error) {
			n, err := d.Node()
			if err != nil {
				return nil, err
			}
			return n, nil
		},
		Find: dir.Find,
		Now:  d.deps.Now,
	})
	user := d.deps.OnUpdate
	d.deps.OnUpdate = func(u pipeline.Update) {
		d.caller.Update(u)
		if user != nil {
			user(u)
		}
	}
	for name, m := range d.caller.Methods() {
		d.srv.Methods[name] = m
	}
}
