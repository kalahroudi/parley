// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/pipeline"
)

func TestEchoBotAnswersWithThePrefixedTaskAndRefusesALongOne(t *testing.T) {
	got, err := echoBot{}.Handle(context.Background(), bot.Task{Content: []byte("hello")}, nil)
	if err != nil || string(got) != TestBotPrefix+"hello" {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := (echoBot{}).Handle(context.Background(), bot.Task{Content: make([]byte, MaxTestTask)}, nil); err != nil || len(got) != len(TestBotPrefix)+MaxTestTask {
		t.Fatalf("the longest task was refused: %v", err)
	}
	_, err = echoBot{}.Handle(context.Background(), bot.Task{Content: make([]byte, MaxTestTask+1)}, nil)
	var f *bot.Failure
	if !errors.As(err, &f) || strings.Contains(f.Message, "\x00") {
		t.Fatalf("%v", err)
	}
}

// The test bot is the daemon's bot unless it is switched off or a real bot was supplied; the allowlist is the
// owner of the device's own recorded binding.
func TestTestBotIsTheDefaultBotAndAllowsOnlyTheDevicesOwner(t *testing.T) {
	e := newEnv(t)
	r := e.start(t, func(d *Deps) { d.AllowUnlockedMemory = true })
	if r.d.host == nil || r.d.deps.Allow == nil || r.d.deps.OnInbound == nil {
		t.Fatal("no test bot by default")
	}
	if r.d.allowOwner("o@x.test") {
		t.Fatal("anyone was allowed before the device had a binding")
	}
	enroll(t, e, r) // owner o@x.test
	for owner, want := range map[string]bool{"o@x.test": true, "O@X.Test": true, "other@x.test": false, "": false, "o@x.test.evil": false} {
		if got := r.d.allowOwner(owner); got != want {
			t.Errorf("allowOwner(%q) = %v, want %v", owner, got, want)
		}
	}
}

func TestTestBotCanBeDisabledAndGivesWayToARealBot(t *testing.T) {
	e := newEnv(t)
	e.cfg.DisableTestBot = true
	d, err := New(e.cfg, e.dirs, e.deps())
	if err != nil {
		t.Fatal(err)
	}
	if d.host != nil || d.deps.Allow != nil || d.deps.OnInbound != nil {
		t.Fatal("a disabled test bot is still wired")
	}
	d.closeHost() // nothing to close

	e = newEnv(t)
	deps := e.deps()
	allow := func(string) bool { return true }
	deps.Allow = allow
	d, err = New(e.cfg, e.dirs, deps)
	if err != nil {
		t.Fatal(err)
	}
	if d.host != nil || d.deps.OnInbound != nil {
		t.Fatal("the test bot replaced a supplied allowlist")
	}
	e = newEnv(t)
	deps = e.deps()
	deps.OnInbound = func(pipeline.Inbound) {}
	if d, err = New(e.cfg, e.dirs, deps); err != nil || d.host != nil || d.deps.Allow != nil {
		t.Fatalf("the test bot replaced a supplied bot: %v", err)
	}
}

func TestTestBotRespondsThroughThePipelineOnceEnrolled(t *testing.T) {
	e := newEnv(t)
	r := e.start(t, func(d *Deps) { d.AllowUnlockedMemory = true })
	resp := nodeResponder{r.d}
	if err := resp.Respond(context.Background(), [16]byte{1}, envelope.TypeResult, []byte("x")); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("%v", err)
	}
	enroll(t, e, r)
	if err := resp.Respond(context.Background(), [16]byte{1}, envelope.TypeResult, []byte("x")); err == nil || errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("a reply to a task nobody sent was accepted: %v", err)
	}
}

// Peers are found through the configured gateway unless a directory is supplied.
func TestDirectoryDefaultsToTheGatewayAndYieldsToASuppliedOne(t *testing.T) {
	e := newEnv(t)
	d, err := New(e.cfg, e.dirs, e.deps())
	if err != nil {
		t.Fatal(err)
	}
	if d.deps.Directory == nil {
		t.Fatal("no default directory")
	}
	e = newEnv(t)
	deps := e.deps()
	called := false
	deps.Directory = func(context.Context, string) (*binding.Signed, error) { called = true; return nil, errors.New("x") }
	if d, err = New(e.cfg, e.dirs, deps); err != nil {
		t.Fatal(err)
	}
	d.deps.Directory(context.Background(), "x")
	if !called {
		t.Fatal("the supplied directory was replaced")
	}
}
