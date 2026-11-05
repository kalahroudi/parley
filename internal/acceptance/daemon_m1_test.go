// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// T414: daemons find each other's bindings through the gateway (no injected directory), and the built-in test bot
// answers `parley-cli test`. The gateway here is the pipeline test's, with the rules of the Worker's
// /v1/directory/binding. The same path against the real Worker is tests/m1-echo.test.mjs.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/outbox"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// A daemon with no injected directory fetches a peer's root-signed binding from the gateway, and the task then
// goes through: the test bot of a second device of the same owner answers it, sealed, and nothing readable
// crosses the gateway.
func TestDaemonFindsPeerBindingsThroughTheGateway(t *testing.T) {
	g := newPipeGW(t)
	alice := g.startOK("alice1", nodeOpts{realDirectory: true, testBot: true, owner: "alice@acme.test"})
	g.startOK("alice2", nodeOpts{realDirectory: true, testBot: true, owner: "alice@acme.test"})

	canary := "CANARY-M1-" + time.Now().Format("150405.000000")
	_, st := alice.submit("alice2", canary)
	if st.State != outbox.Sent {
		t.Fatalf("%+v", st)
	}
	g.waitFor("the echo", func() bool { alice.mu.Lock(); defer alice.mu.Unlock(); return finals(alice.ups) == 1 })
	alice.mu.Lock()
	last := alice.ups[len(alice.ups)-1]
	alice.mu.Unlock()
	if last.Type != envelope.TypeResult || string(last.Content) != daemon.TestBotPrefix+canary {
		t.Fatalf("answer %v %q", last.Type, last.Content)
	}
	if g.dirCalls.Load() == 0 {
		t.Fatal("the daemons never asked the gateway for a binding")
	}
	all := g.everything()
	if bytes.Contains(all, []byte(canary)) {
		t.Fatal("the task text crossed the gateway in the clear")
	}
	if !bytes.Contains(all, []byte(`{"device":"alice2"}`)) {
		t.Fatal("the lookup did not name the device it wanted")
	}
}

// The test bot answers its owner's devices and nobody else, and a daemon never answers itself.
func TestTestBotAnswersOnlyTheOwnersDevices(t *testing.T) {
	g := newPipeGW(t)
	bob := g.startOK("bob1", nodeOpts{realDirectory: true, testBot: true})
	alice := g.startOK("alice1", nodeOpts{realDirectory: true, testBot: true})
	if _, st := alice.submit("bob1", "x"); st.State != outbox.Failed || !errors.Is(st.Err, pipeline.ErrRefused) {
		t.Fatalf("a stranger's task was not refused: %+v", st)
	}
	if _, st := bob.submit("bob1", "x"); st.State != outbox.Failed {
		t.Fatalf("a device answered itself: %+v", st)
	}
	if g.a2a.Load() != 0 {
		t.Fatal("a task was sent to a bot that refuses its caller")
	}
}

// The gateway is only a source of bindings: whatever it answers is verified by the daemon, so a gateway that
// substitutes, forges, expires, rolls back or withholds a binding stops the task before anything is sent.
func TestDaemonRefusesWhatAHostileDirectoryAnswers(t *testing.T) {
	g := newPipeGW(t)
	bob := g.startOK("alice2", nodeOpts{realDirectory: true, testBot: true, owner: "alice@acme.test"})
	g.startOK("mallory", nodeOpts{realDirectory: true})
	_, otherRoot, _ := ed25519.GenerateKey(rand.Reader)

	signed := func(root ed25519.PrivateKey, mod func(*binding.Binding)) func(string, string) (int, string, bool) {
		b := bob.bind.Binding
		mod(&b)
		s, err := binding.Sign(root, b)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(map[string]any{"binding": s})
		return func(_, _ string) (int, string, bool) { return 200, string(raw), true }
	}
	status := func(code int, body string) func(string, string) (int, string, bool) {
		return func(_, _ string) (int, string, bool) { return code, body, true }
	}
	g.mu.Lock()
	malloryBinding, _ := json.Marshal(map[string]any{"binding": g.devs["mallory"].bind})
	g.mu.Unlock()

	// A probe is a fresh daemon: one keeps the binding it has verified, so it asks once per peer.
	n := 0
	probe := func(name string, hook func(string, string) (int, string, bool), seed func(*pipeNode)) outbox.Status {
		t.Helper()
		g.mu.Lock()
		g.dirHook = hook
		g.mu.Unlock()
		n++
		p := g.startOK("probe"+string(rune('a'+n)), nodeOpts{realDirectory: true, owner: "alice@acme.test"})
		if seed != nil {
			seed(p)
		}
		node := p.node()
		asked := g.dirCalls.Load()
		defer func() {
			if g.dirCalls.Load() == asked {
				t.Errorf("%s: the daemon never asked the gateway", name)
			}
		}()
		id, err := node.Submit(pipeline.Request{Target: "alice2", Content: []byte("x"), Expiry: time.Now().Add(10 * time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		defer node.Abandon(id)
		select {
		case <-node.Done(id):
		case <-time.After(1500 * time.Millisecond):
			// Still being retried: the outbox waits for a directory that fails or is unreachable.
			return outbox.Status{State: outbox.Waiting}
		}
		st, _ := node.Status(id)
		return st
	}

	for name, hook := range map[string]func(string, string) (int, string, bool){
		"another device's binding":   status(200, string(malloryBinding)),
		"signed by another root":     signed(otherRoot, func(*binding.Binding) {}),
		"a binding that has expired": signed(g.rootKey, func(b *binding.Binding) { b.NotAfter = time.Now().Add(-time.Hour) }),
		"another tenant's binding":   signed(g.rootKey, func(b *binding.Binding) { b.Tenant = "other" }),
		"a changed signing key":      signed(g.rootKey, func(b *binding.Binding) { b.SigningKey = make([]byte, 32) }),
	} {
		if st := probe(name, hook, nil); st.State != outbox.Failed && st.State != outbox.Waiting {
			t.Errorf("%s: %+v", name, st)
		}
	}
	// A device the gateway does not know ends the task at once; a gateway that fails or says nothing is waited out
	// (nothing is sent either way).
	if st := probe("not found", status(404, `{"error":"not_found"}`), nil); st.State != outbox.Failed || !errors.Is(st.Err, outbox.ErrGone) {
		t.Errorf("not found: %+v", st)
	}
	for name, hook := range map[string]func(string, string) (int, string, bool){"500": status(500, "SECRET"), "empty": status(200, `{}`)} {
		if st := probe(name, hook, nil); st.State != outbox.Waiting {
			t.Errorf("%s: %+v", name, st)
		}
	}
	// A binding older than one the daemon has already recorded is a rollback, whoever serves it.
	newer := bob.bind.Binding
	newer.Version = 2
	v2, err := binding.Sign(g.rootKey, newer)
	if err != nil {
		t.Fatal(err)
	}
	if st := probe("rollback", nil, func(p *pipeNode) {
		if err := p.d.Trust().Tracker.Accept(v2, time.Now()); err != nil {
			t.Fatal(err)
		}
	}); st.State != outbox.Failed {
		t.Errorf("rollback: %+v", st)
	}
	if g.a2a.Load() != 0 || bob.inboxLen() != 0 {
		t.Fatalf("something was sent (%d) or delivered (%d) on a hostile directory's word", g.a2a.Load(), bob.inboxLen())
	}
}
