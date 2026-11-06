// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package approval

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/pipeline"
)

type sent struct {
	typ     envelope.Type
	content string
}

// responder records what the host sends to the caller.
type responder struct {
	mu  sync.Mutex
	got []sent
}

func (r *responder) Respond(_ context.Context, _ [16]byte, typ envelope.Type, content []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, sent{typ, string(content)})
	return nil
}

func (r *responder) wait(t *testing.T, n int) []sent {
	t.Helper()
	for i := 0; i < 5000; i++ {
		r.mu.Lock()
		got := append([]sent(nil), r.got...)
		r.mu.Unlock()
		if len(got) >= n {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("fewer than %d messages", n)
	return nil
}

func host(t *testing.T, cfg Config) (*Gate, *recorder, *responder, *bot.Host) {
	t.Helper()
	g, r := newGate(t, cfg)
	resp := &responder{}
	h, err := bot.NewHost(bot.Config{Bot: g, Responder: resp})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return g, r, resp, h
}

func inbound(typ envelope.Type, n byte, text string) pipeline.Inbound {
	return pipeline.Inbound{Type: typ, TaskID: id(n), Caller: "dev-2", Owner: "ann@example.com", Content: []byte(text), Expiry: time.Now().Add(time.Hour)}
}

func TestBehindTheBotHostTheCallerSeesWaitingThenTheResult(t *testing.T) {
	g, r, resp, h := host(t, Config{Mode: Owner})
	h.Inbound(inbound(envelope.TypeTask, 1, "review"))
	waitPending(t, g, 1)
	if got := resp.wait(t, 1); got[0] != (sent{envelope.TypeStatus, TextWaiting}) || r.calls.Load() != 0 {
		t.Fatalf("%v calls %d", got, r.calls.Load())
	}
	if err := g.Decide(id(1), true); err != nil {
		t.Fatal(err)
	}
	got := resp.wait(t, 2)
	if got[1] != (sent{envelope.TypeResult, "ran: review"}) || r.calls.Load() != 1 {
		t.Fatalf("%v", got)
	}
}

func TestBehindTheBotHostADenialAndATimeoutEndTheTaskWithAFixedError(t *testing.T) {
	g, r, resp, h := host(t, Config{Mode: Owner, Timeout: 40 * time.Millisecond, MaxPerCaller: 5})
	h.Inbound(inbound(envelope.TypeTask, 1, "secret one"))
	waitPending(t, g, 1)
	if err := g.Decide(id(1), false); err != nil {
		t.Fatal(err)
	}
	h.Inbound(inbound(envelope.TypeTask, 2, "secret two"))
	got := resp.wait(t, 4)
	finals := map[string]bool{}
	for _, m := range got {
		if m.typ == envelope.TypeError {
			finals[m.content] = true
		}
	}
	if !finals[TextDenied] || !finals[TextTimedOut] || len(finals) != 2 || r.calls.Load() != 0 {
		t.Fatalf("%v calls %d", got, r.calls.Load())
	}
}

func TestBehindTheBotHostACancelWhileWaitingEndsItAndTheBotNeverRuns(t *testing.T) {
	g, r, resp, h := host(t, Config{Mode: Owner})
	h.Inbound(inbound(envelope.TypeTask, 1, "x"))
	waitPending(t, g, 1)
	h.Inbound(inbound(envelope.TypeCancel, 1, ""))
	got := resp.wait(t, 2)
	if got[1].typ != envelope.TypeCancel || r.calls.Load() != 0 {
		t.Fatalf("%v", got)
	}
	waitPending(t, g, 0)
}
