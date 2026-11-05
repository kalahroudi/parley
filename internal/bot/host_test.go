// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package bot_test

import (
	"context"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/bot/bottest"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/pipeline"
)

func TestConfig(t *testing.T) {
	if _, err := bot.NewHost(bot.Config{}); err != bot.ErrConfig {
		t.Fatal(err)
	}
	if _, err := bot.NewHost(bot.Config{Bot: &bottest.Fake{}}); err != bot.ErrConfig {
		t.Fatal(err)
	}
	h, err := bot.NewHost(bot.Config{Bot: &bottest.Fake{}, Responder: bottest.NewRecorder(), MaxQueued: -1})
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
}

// capture is a bot that keeps what it was given, to see what Host does to it.
type capture struct {
	task bot.Task
	sess bot.Session
	done chan struct{}
}

func (c *capture) Handle(_ context.Context, t bot.Task, s bot.Session) ([]byte, error) {
	c.task, c.sess = t, s
	close(c.done)
	return nil, nil
}

func TestContentCopiedAndZeroed(t *testing.T) {
	c := &capture{done: make(chan struct{})}
	rec := bottest.NewRecorder()
	h, _ := bot.NewHost(bot.Config{Bot: c, Responder: rec})
	defer h.Close()
	in := []byte("secret task")
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{1}, Caller: "d", Owner: "o", Context: "c", Content: in})
	<-c.done
	if string(in) != "secret task" {
		t.Fatal("Host changed the pipeline's buffer instead of its own copy")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rec.Wait(ctx, [16]byte{1}, 1)
	for _, b := range c.task.Content {
		if b != 0 {
			t.Fatal("task content was not zeroed after Handle")
		}
	}
	if c.task.Caller != "d" || c.task.Owner != "o" || c.task.Context != "c" {
		t.Fatalf("task fields: %+v", c.task)
	}
	if err := c.sess.Status(ctx, []byte("late")); err != bot.ErrClosed {
		t.Fatalf("Status after Handle: %v", err)
	}
	if _, err := c.sess.Ask(ctx, []byte("late")); err != bot.ErrClosed {
		t.Fatalf("Ask after Handle: %v", err)
	}
}

func TestReplyForUnknownTaskAndNoQuestionIsDropped(t *testing.T) {
	rec := bottest.NewRecorder()
	h, _ := bot.NewHost(bot.Config{Bot: &bottest.Fake{}, Responder: rec})
	defer h.Close()
	h.Inbound(pipeline.Inbound{Type: envelope.TypeReply, TaskID: [16]byte{7}, Content: []byte("x")})
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{1}, Content: []byte("block")})
	for i := 0; i < 3; i++ { // the buffer holds one: the rest must not block the pipeline
		h.Inbound(pipeline.Inbound{Type: envelope.TypeReply, TaskID: [16]byte{1}, Content: []byte("x")})
	}
	if len(rec.Messages([16]byte{7})) != 0 {
		t.Fatal("a reply for an unknown task produced a message")
	}
}

func TestResponderFailureOnAskEndsTheTask(t *testing.T) {
	rec := &failing{Recorder: bottest.NewRecorder()}
	h, _ := bot.NewHost(bot.Config{Bot: &bottest.Fake{}, Responder: rec})
	defer h.Close()
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{1}, Content: []byte("ask q")})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m := rec.Wait(ctx, [16]byte{1}, 1)
	if len(m) != 1 || m[0].Type != envelope.TypeError || m[0].Content != bot.TextFailed {
		t.Fatalf("%v", m)
	}
}

type failing struct{ *bottest.Recorder }

func (f *failing) Respond(ctx context.Context, id [16]byte, typ envelope.Type, c []byte) error {
	if typ == envelope.TypeInputRequired {
		return pipeline.ErrState
	}
	return f.Recorder.Respond(ctx, id, typ, c)
}

func TestFailureError(t *testing.T) {
	if (&bot.Failure{Message: "m"}).Error() != "m" {
		t.Fatal("Failure.Error")
	}
}

func TestCancelWhileAskingEndsWithAcknowledgment(t *testing.T) {
	rec := bottest.NewRecorder()
	h, _ := bot.NewHost(bot.Config{Bot: &bottest.Fake{}, Responder: rec})
	defer h.Close()
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{1}, Content: []byte("ask q")})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rec.Wait(ctx, [16]byte{1}, 1)
	h.Inbound(pipeline.Inbound{Type: envelope.TypeCancel, TaskID: [16]byte{1}})
	m := rec.Wait(ctx, [16]byte{1}, 2)
	if len(m) != 2 || m[1].Type != envelope.TypeCancel {
		t.Fatalf("%v", m)
	}
}

func TestFakeMeetsContract(t *testing.T) {
	bottest.Contract(t, func(*testing.T) bot.Bot { return &bottest.Fake{} })
}
