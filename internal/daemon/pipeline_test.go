// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/frames"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/pipeline"
	"github.com/kalahroudi/parley/internal/receive"
	"github.com/kalahroudi/parley/internal/tunnel"
)

// enroll records a root-signed binding for the daemon's own device, as enrollment will.
func enroll(t *testing.T, e *env, r *running) {
	t.Helper()
	b, err := binding.Sign(e.root, binding.Binding{Tenant: "t1", Owner: "o@x.test", DeviceID: "dev-1", SigningKey: r.d.SigningKey().Public().(ed25519.PublicKey),
		Version: 1, NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.d.Trust().Tracker.Accept(b, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestNodeNeedsAnEnrolledDevice(t *testing.T) {
	e := newEnv(t)
	r := e.start(t, func(d *Deps) { d.AllowUnlockedMemory = true })
	if _, err := r.d.Node(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("%v", err)
	}
	enroll(t, e, r)
	n, err := r.d.Node()
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := r.d.Node(); again != n {
		t.Fatal("a second call built a second pipeline (a second set of prekeys)")
	}
}

// With no bot configured the pipeline fails closed (nobody may start a task), and a gateway that cannot vouch for
// a peer (here one with no directory at all) finds nobody.
func TestNodeFailsClosedWithoutBotAndFindsNobodyThroughAGatewayWithoutOne(t *testing.T) {
	e := newEnv(t)
	r := e.start(t, func(d *Deps) { d.AllowUnlockedMemory = true })
	enroll(t, e, r)
	// The pipeline refuses everything without a fresh revocation list; the refresh loop fetches one a moment after start.
	waitFor(t, "revocation list fetched", func() bool { return status(t, e).Revocations == "" })
	n, err := r.d.Node()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Submit(pipeline.Request{Target: "bob", Content: []byte("x"), Expiry: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	// The default directory asks the gateway, which has nothing for bob.
	if err := n.HandleEvent(context.Background(), tunnel.Event{Body: `{"t":"prekey_request","id":"r","from":"bob","nonce":"AQID","expires_at":4102444800000}`}); !errors.Is(err, pipeline.ErrPeer) {
		t.Fatalf("%v", err)
	}
}

func TestRelayNeedsATunnel(t *testing.T) {
	e := newEnv(t)
	d, err := New(e.cfg, e.dirs, e.deps())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.relay("x"); !errors.Is(err, tunnel.ErrClosed) {
		t.Fatalf("%v", err)
	}
	d.tun.Store(tunnel.New(tunnel.Config{URL: "ws://127.0.0.1:1"}))
	if err := d.relay("x"); err != nil {
		t.Fatal(err)
	}
}

func TestHandleEventLogsTheClassOfADroppedMessageAndNothingElse(t *testing.T) {
	e := newEnv(t)
	var tapped int
	r := e.start(t, func(d *Deps) {
		d.AllowUnlockedMemory = true
		d.OnEvent = func(tunnel.Event) { tapped++ }
	})
	secret := "SECRET-" + fmt.Sprint(time.Now().UnixNano())
	ev := tunnel.Event{Body: `{"x":"` + secret + `"}`}
	r.d.handleEvent(context.Background(), ev) // not enrolled yet: no pipeline
	enroll(t, e, r)
	r.d.handleEvent(context.Background(), ev)
	r.d.handleEvent(context.Background(), tunnel.Event{Body: `{"t":"prekey_reply","id":"unmatched","from":"p","prekey":"AAAA"}`}) // handled: nothing to log
	out := e.log.String()
	if tapped != 3 {
		t.Fatalf("tap saw %d events", tapped)
	}
	if !strings.Contains(out, "type=not_ready") || strings.Count(out, "message dropped") != 2 || strings.Contains(out, secret) {
		t.Fatalf("log: %s", out)
	}
}

func TestDropFieldNamesAClassFromAFixedSet(t *testing.T) {
	cases := []struct {
		want string
		err  error
	}{
		{"dropped", receive.ErrDropped}, {"expired", receive.ErrExpired}, {"rejected", receive.ErrRejected}, {"rejected", pipeline.ErrPeer},
		{"format", frames.ErrFormat}, {"format", frames.ErrUnsupported}, {"format", envelope.ErrInvalid}, {"failed", errors.New("anything else, with a secret")},
	}
	for _, c := range cases {
		f, dropped := dropField(fmt.Errorf("wrapped: %w", c.err))
		var buf syncBuf
		logx.New(&buf).Warn("m", f)
		if !dropped || !strings.Contains(buf.String(), "type="+c.want+"\n") || strings.Contains(buf.String(), "secret") {
			t.Errorf("%v: dropped=%v log=%s", c.err, dropped, buf.String())
		}
	}
	if _, dropped := dropField(nil); dropped {
		t.Fatal("a handled message was reported as dropped")
	}
}

func TestSweepRunsUntilStopped(t *testing.T) {
	e := newEnv(t)
	r := e.start(t, func(d *Deps) { d.AllowUnlockedMemory = true; d.SweepEvery = time.Millisecond })
	time.Sleep(10 * time.Millisecond) // ticks with no pipeline yet
	enroll(t, e, r)
	if _, err := r.d.Node(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // ticks with one
	r.cancel()
	if err := <-r.done; err != nil {
		t.Fatal(err)
	}
	if r.d.node != nil {
		t.Fatal("the pipeline (and its prekeys) outlived Run")
	}
	r.done <- nil
}
