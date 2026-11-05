// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package bottest

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// Factory returns the bot under test, which must behave as a Fake does for the
// scripts in the package comment. Cleanup is registered on t.
type Factory func(t *testing.T) bot.Bot

const wait = 10 * time.Second

func id(n byte) [16]byte { return [16]byte{n} }

type rig struct {
	t   *testing.T
	h   *bot.Host
	rec *Recorder
}

func newRig(t *testing.T, f Factory, cfg bot.Config) *rig {
	t.Helper()
	rec := NewRecorder()
	cfg.Bot, cfg.Responder = f(t), rec
	h, err := bot.NewHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return &rig{t: t, h: h, rec: rec}
}

func (r *rig) task(n byte, script string) {
	r.h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: id(n), Caller: "dev-a", Owner: "a@example.com",
		Content: []byte(script), Expiry: time.Now().Add(time.Hour)})
}

func (r *rig) await(n byte, count int) []Message {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	m := r.rec.Wait(ctx, id(n), count)
	if len(m) < count {
		r.t.Fatalf("task %d: got %d messages, want %d: %v", n, len(m), count, m)
	}
	return m
}

func (r *rig) final(n byte, count int, typ envelope.Type, content string) []Message {
	r.t.Helper()
	m := r.await(n, count)
	last := m[len(m)-1]
	if last.Type != typ || last.Content != content {
		r.t.Fatalf("task %d: final message %v %q, want %v %q", n, last.Type, last.Content, typ, content)
	}
	return m
}

// Contract runs the adapter contract against the bot a Factory returns.
func Contract(t *testing.T, f Factory) {
	t.Run("result", func(t *testing.T) {
		r := newRig(t, f, bot.Config{})
		r.task(1, "echo hi")
		r.final(1, 1, envelope.TypeResult, "echo hi")
	})
	t.Run("status then result", func(t *testing.T) {
		r := newRig(t, f, bot.Config{})
		r.task(1, "status working")
		m := r.final(1, 2, envelope.TypeResult, "done")
		if m[0].Type != envelope.TypeStatus || m[0].Content != "working" {
			t.Fatalf("first message %v", m[0])
		}
	})
	t.Run("question and answer on the same task", func(t *testing.T) {
		r := newRig(t, f, bot.Config{})
		r.task(1, "ask which?")
		m := r.await(1, 1)
		if m[0].Type != envelope.TypeInputRequired || m[0].Content != "which?" {
			t.Fatalf("first message %v", m[0])
		}
		r.h.Inbound(pipeline.Inbound{Type: envelope.TypeReply, TaskID: id(1), Content: []byte("blue")})
		r.final(1, 2, envelope.TypeResult, "answer: blue")
	})
	t.Run("a declared failure reaches the caller", func(t *testing.T) {
		r := newRig(t, f, bot.Config{})
		r.task(1, "fail no such file")
		r.final(1, 1, envelope.TypeError, "no such file")
	})
	t.Run("a failure text is cut to its limit", func(t *testing.T) {
		r := newRig(t, f, bot.Config{})
		r.task(1, "fail "+strings.Repeat("a", bot.MaxFailure+50))
		m := r.await(1, 1)
		if len(m[0].Content) != bot.MaxFailure {
			t.Fatalf("failure text is %d bytes", len(m[0].Content))
		}
	})
	t.Run("other errors and panics never reveal what they carry", func(t *testing.T) {
		r := newRig(t, f, bot.Config{})
		r.task(1, "leak SECRET-CANARY")
		r.final(1, 1, envelope.TypeError, bot.TextFailed)
		r.task(2, "panic SECRET-CANARY")
		r.final(2, 1, envelope.TypeError, bot.TextFailed)
		r.task(3, "echo still works")
		r.final(3, 1, envelope.TypeResult, "echo still works")
	})
	t.Run("an oversized result becomes an error", func(t *testing.T) {
		r := newRig(t, f, bot.Config{})
		r.task(1, "big")
		r.final(1, 1, envelope.TypeError, bot.TextTooLarge)
	})
	t.Run("cancel stops the bot and is acknowledged once", func(t *testing.T) {
		r := newRig(t, f, bot.Config{})
		r.task(1, "block")
		r.h.Inbound(pipeline.Inbound{Type: envelope.TypeCancel, TaskID: id(1)})
		m := r.final(1, 1, envelope.TypeCancel, "")
		time.Sleep(50 * time.Millisecond)
		if got := r.rec.Messages(id(1)); len(got) != len(m) {
			t.Fatalf("messages after the acknowledgment: %v", got)
		}
	})
	t.Run("cancel of a task that is not running is acknowledged", func(t *testing.T) {
		r := newRig(t, f, bot.Config{})
		r.h.Inbound(pipeline.Inbound{Type: envelope.TypeCancel, TaskID: id(9)})
		r.final(9, 1, envelope.TypeCancel, "")
	})
	t.Run("the task's expiry and the timeout end the bot", func(t *testing.T) {
		r := newRig(t, f, bot.Config{Timeout: 100 * time.Millisecond})
		r.task(1, "block")
		r.final(1, 1, envelope.TypeError, bot.TextTimedOut)
		r.h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: id(2), Content: []byte("block"), Expiry: time.Now().Add(50 * time.Millisecond)})
		r.final(2, 1, envelope.TypeError, bot.TextTimedOut)
	})
	t.Run("busy: running and queued are capped, the rest are rejected", func(t *testing.T) {
		r := newRig(t, f, bot.Config{MaxRunning: 1, MaxQueued: 1})
		r.task(1, "block")
		r.task(2, "block")
		r.task(3, "echo x") // one running, one queued: this one is over the cap
		r.final(3, 1, envelope.TypeError, bot.TextBusy)
		r.h.Inbound(pipeline.Inbound{Type: envelope.TypeCancel, TaskID: id(1)})
		r.final(1, 1, envelope.TypeCancel, "")
		r.h.Inbound(pipeline.Inbound{Type: envelope.TypeCancel, TaskID: id(2)})
		r.final(2, 1, envelope.TypeCancel, "")
		r.task(4, "echo y") // capacity is free again
		r.final(4, 1, envelope.TypeResult, "echo y")
	})
	t.Run("a repeated task id is not run twice and does not end the live task", func(t *testing.T) {
		r := newRig(t, f, bot.Config{})
		r.task(1, "block")
		r.task(1, "echo again")
		time.Sleep(50 * time.Millisecond)
		if m := r.rec.Messages(id(1)); len(m) != 0 {
			t.Fatalf("a repeat answered for the live task: %v", m)
		}
		r.h.Inbound(pipeline.Inbound{Type: envelope.TypeCancel, TaskID: id(1)})
		r.final(1, 1, envelope.TypeCancel, "")
	})
	t.Run("no goroutines are left behind", func(t *testing.T) {
		base := runtime.NumGoroutine()
		for i := 0; i < 3; i++ {
			r := newRig(t, f, bot.Config{})
			r.task(1, "echo x")
			r.final(1, 1, envelope.TypeResult, "echo x")
			r.task(2, "block")
			r.task(3, "ask q")
			r.await(3, 1)
			r.h.Close()
		}
		deadline := time.Now().Add(wait)
		for runtime.NumGoroutine() > base && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if n := runtime.NumGoroutine(); n > base {
			t.Fatalf("%d goroutines before, %d after", base, n)
		}
	})
	t.Run("close cancels running bots and waits for them", func(t *testing.T) {
		r := newRig(t, f, bot.Config{})
		r.task(1, "block")
		r.h.Close()
		time.Sleep(20 * time.Millisecond)
		if m := r.rec.Messages(id(1)); len(m) != 0 {
			t.Fatalf("messages after close: %v", m)
		}
		r.task(2, "echo late")
		if m := r.rec.Messages(id(2)); len(m) != 1 || m[0].Content != bot.TextBusy {
			t.Fatalf("a task after close: %v", m)
		}
	})
}
