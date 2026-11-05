// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package bot_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

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

// scripted runs a function as the bot.
type scripted func(ctx context.Context, t bot.Task, s bot.Session) ([]byte, error)

func (f scripted) Handle(ctx context.Context, t bot.Task, s bot.Session) ([]byte, error) {
	return f(ctx, t, s)
}

func runOne(t *testing.T, cfg bot.Config, content string, expiry time.Time) (*bottest.Recorder, *bot.Host) {
	t.Helper()
	rec := bottest.NewRecorder()
	cfg.Responder = rec
	h, err := bot.NewHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{1}, Content: []byte(content), Expiry: expiry})
	return rec, h
}

func final(t *testing.T, rec *bottest.Recorder, n int) []bottest.Message {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m := rec.Wait(ctx, [16]byte{1}, n)
	if len(m) < n {
		t.Fatalf("got %v", m)
	}
	return m
}

func TestTypedNilAndWrappedFailure(t *testing.T) {
	var nilFailure *bot.Failure
	rec, _ := runOne(t, bot.Config{Bot: scripted(func(context.Context, bot.Task, bot.Session) ([]byte, error) {
		return nil, nilFailure
	})}, "x", time.Time{})
	if m := final(t, rec, 1); m[0].Content != bot.TextFailed {
		t.Fatal(m)
	}
	rec, _ = runOne(t, bot.Config{Bot: scripted(func(context.Context, bot.Task, bot.Session) ([]byte, error) {
		return nil, fmt.Errorf("wrap: %w", &bot.Failure{Message: "declared"})
	})}, "x", time.Time{})
	if m := final(t, rec, 1); m[0].Content != "declared" {
		t.Fatal(m)
	}
	rec, _ = runOne(t, bot.Config{Bot: scripted(func(context.Context, bot.Task, bot.Session) ([]byte, error) {
		return nil, &bot.Failure{Message: "\xff\xfe"}
	})}, "x", time.Time{})
	if m := final(t, rec, 1); m[0].Content != bot.TextFailed {
		t.Fatal(m)
	}
}

func TestFailureCutKeepsValidUTF8(t *testing.T) {
	msg := strings.Repeat("a", bot.MaxFailure-1) + "é" // the cut lands inside the 2-byte rune
	rec, _ := runOne(t, bot.Config{Bot: scripted(func(context.Context, bot.Task, bot.Session) ([]byte, error) {
		return nil, &bot.Failure{Message: msg}
	})}, "x", time.Time{})
	if m := final(t, rec, 1); !utf8.ValidString(m[0].Content) || len(m[0].Content) != bot.MaxFailure-1 {
		t.Fatalf("%d bytes, valid=%v", len(m[0].Content), utf8.ValidString(m[0].Content))
	}
}

func TestExpiredTaskNeverReachesTheBot(t *testing.T) {
	for i := 0; i < 100; i++ {
		var called atomic.Bool
		rec, _ := runOne(t, bot.Config{Bot: scripted(func(context.Context, bot.Task, bot.Session) ([]byte, error) {
			called.Store(true)
			return nil, nil
		})}, "x", time.Now().Add(-time.Second))
		if m := final(t, rec, 1); m[0].Content != bot.TextTimedOut {
			t.Fatal(m)
		}
		if called.Load() {
			t.Fatal("an expired task was handed to the bot")
		}
	}
}

func TestGoexitIsAFailure(t *testing.T) {
	rec, _ := runOne(t, bot.Config{Bot: scripted(func(context.Context, bot.Task, bot.Session) ([]byte, error) {
		runtime.Goexit()
		return nil, nil
	})}, "x", time.Time{})
	if m := final(t, rec, 1); m[0].Content != bot.TextFailed {
		t.Fatal(m)
	}
}

func TestBotThatIgnoresItsContext(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	var second atomic.Bool
	b := scripted(func(_ context.Context, tk bot.Task, _ bot.Session) ([]byte, error) {
		if tk.ID == ([16]byte{2}) {
			second.Store(true)
			return []byte("ok"), nil
		}
		started <- struct{}{}
		<-release // ignores ctx
		return nil, nil
	})
	rec := bottest.NewRecorder()
	h, _ := bot.NewHost(bot.Config{Bot: b, Responder: rec, MaxRunning: 1, MaxQueued: 1, Timeout: 50 * time.Millisecond, Grace: 50 * time.Millisecond})
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{1}, Content: []byte("x")})
	<-started
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{2}, Content: []byte("y")})
	m := final(t, rec, 1)
	if m[0].Type != envelope.TypeError || m[0].Content != bot.TextTimedOut {
		t.Fatal(m)
	}
	// The stuck bot still holds the only slot: the queued task times out without running.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if m2 := rec.Wait(ctx, [16]byte{2}, 1); len(m2) != 1 || m2[0].Content != bot.TextTimedOut || second.Load() {
		t.Fatalf("%v ran=%v", m2, second.Load())
	}
	done := make(chan struct{})
	go func() { h.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close waited for a bot that ignores its context")
	}
	close(release) // the abandoned goroutine ends and frees its slot
}

func TestSessionCallsEndWithTheTask(t *testing.T) {
	// A bot that passes context.Background() must still be released when the task ends.
	errs := make(chan error, 2)
	b := scripted(func(_ context.Context, _ bot.Task, s bot.Session) ([]byte, error) {
		_, err := s.Ask(context.Background(), []byte("q"))
		errs <- err
		return nil, err
	})
	rec, h := runOne(t, bot.Config{Bot: b}, "x", time.Time{})
	final(t, rec, 1)
	h.Inbound(pipeline.Inbound{Type: envelope.TypeCancel, TaskID: [16]byte{1}})
	select {
	case err := <-errs:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Ask did not end with the task")
	}
}

// blocking is a Responder that waits for its context.
type blocking struct{ *bottest.Recorder }

func (b blocking) Respond(ctx context.Context, id [16]byte, typ envelope.Type, c []byte) error {
	if typ == envelope.TypeStatus {
		<-ctx.Done()
		return ctx.Err()
	}
	return b.Recorder.Respond(ctx, id, typ, c)
}

func TestStatusEndsWithTheTask(t *testing.T) {
	rec := blocking{bottest.NewRecorder()}
	errs := make(chan error, 1)
	b := scripted(func(_ context.Context, _ bot.Task, s bot.Session) ([]byte, error) {
		err := s.Status(context.Background(), []byte("s"))
		errs <- err
		return nil, err
	})
	h, _ := bot.NewHost(bot.Config{Bot: b, Responder: rec})
	defer h.Close()
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{1}, Content: []byte("x")})
	time.Sleep(50 * time.Millisecond)
	h.Inbound(pipeline.Inbound{Type: envelope.TypeCancel, TaskID: [16]byte{1}})
	select {
	case err := <-errs:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Status did not end with the task")
	}
}

// refuseResult is a Responder that refuses a RESULT once.
type refuseResult struct{ *bottest.Recorder }

func (r refuseResult) Respond(ctx context.Context, id [16]byte, typ envelope.Type, c []byte) error {
	if typ == envelope.TypeResult {
		return errors.New("transport down")
	}
	return r.Recorder.Respond(ctx, id, typ, c)
}

func TestFailedResultSendEndsTheTaskWithAnError(t *testing.T) {
	rec := refuseResult{bottest.NewRecorder()}
	h, _ := bot.NewHost(bot.Config{Bot: &bottest.Fake{}, Responder: rec})
	defer h.Close()
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{1}, Content: []byte("echo x")})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if m := rec.Wait(ctx, [16]byte{1}, 1); len(m) != 1 || m[0].Content != bot.TextFailed {
		t.Fatal(m)
	}
}

func TestCloseRacesWithInbound(t *testing.T) {
	for i := 0; i < 50; i++ {
		rec := bottest.NewRecorder()
		h, _ := bot.NewHost(bot.Config{Bot: &bottest.Fake{}, Responder: rec})
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func(j int) {
				defer wg.Done()
				h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{byte(j + 1)}, Content: []byte("block")})
			}(j)
		}
		h.Close()
		wg.Wait()
		h.Close()
	}
}

func TestConstantsArePinned(t *testing.T) {
	if bot.DefaultMaxRunning != 5 || bot.DefaultMaxQueued != 5 || bot.DefaultTimeout != 15*time.Minute ||
		bot.DefaultGrace != 5*time.Second || bot.MaxFailure != 1024 {
		t.Fatal("a limit changed")
	}
}

func TestDefaultsFiveRunningFiveQueued(t *testing.T) {
	rec := bottest.NewRecorder()
	h, _ := bot.NewHost(bot.Config{Bot: &bottest.Fake{}, Responder: rec})
	defer h.Close()
	for i := byte(1); i <= 11; i++ {
		h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{i}, Content: []byte("block")})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if m := rec.Wait(ctx, [16]byte{11}, 1); len(m) != 1 || m[0].Content != bot.TextBusy {
		t.Fatalf("the 11th task: %v", m)
	}
	time.Sleep(50 * time.Millisecond)
	for i := byte(1); i <= 10; i++ {
		if m := rec.Messages([16]byte{i}); len(m) != 0 {
			t.Fatalf("task %d was rejected: %v", i, m)
		}
	}
}

func TestLimitsAtTheBoundary(t *testing.T) {
	big := make([]byte, pipeline.MaxContent)
	rec, _ := runOne(t, bot.Config{Bot: scripted(func(context.Context, bot.Task, bot.Session) ([]byte, error) {
		return big, nil
	})}, "x", time.Time{})
	if m := final(t, rec, 1); m[0].Type != envelope.TypeResult || len(m[0].Content) != pipeline.MaxContent {
		t.Fatalf("a result of exactly the limit: %v", m[0].Type)
	}
	rec, _ = runOne(t, bot.Config{Bot: scripted(func(context.Context, bot.Task, bot.Session) ([]byte, error) {
		return nil, &bot.Failure{Message: strings.Repeat("a", bot.MaxFailure)}
	})}, "x", time.Time{})
	if m := final(t, rec, 1); len(m[0].Content) != bot.MaxFailure {
		t.Fatalf("a failure of exactly the limit is %d bytes", len(m[0].Content))
	}
}

// A bot that returns within the grace period has its buffer zeroed before the
// caller sees the final message (the default grace is long enough to wait).
func TestSlowBotIsWaitedForWithinTheDefaultGrace(t *testing.T) {
	var kept []byte
	rec, _ := runOne(t, bot.Config{Timeout: 20 * time.Millisecond, Bot: scripted(func(_ context.Context, tk bot.Task, _ bot.Session) ([]byte, error) {
		kept = tk.Content
		time.Sleep(150 * time.Millisecond)
		return nil, nil
	})}, "secret", time.Time{})
	if m := final(t, rec, 1); m[0].Content != bot.TextTimedOut {
		t.Fatal(m)
	}
	for _, b := range kept {
		if b != 0 {
			t.Fatal("the final message was sent before the content was zeroed")
		}
	}
}

// A bot's own context ending ends its Ask, whatever the task's context is doing.
// (When the bot passes the task's context, which of the two select cases fires
// first is scheduler luck, so this case needs its own deterministic test.)
func TestAskEndsWithTheBotsOwnContext(t *testing.T) {
	own, stop := context.WithCancel(context.Background())
	rec := bottest.NewRecorder()
	errs := make(chan error, 1)
	b := scripted(func(_ context.Context, tk bot.Task, s bot.Session) ([]byte, error) {
		go func() { // once the question is out, end the bot's own context
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			rec.Wait(ctx, tk.ID, 1)
			stop()
		}()
		_, err := s.Ask(own, []byte("q"))
		errs <- err
		return nil, err
	})
	h, _ := bot.NewHost(bot.Config{Bot: b, Responder: rec})
	defer h.Close()
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{1}, Content: []byte("x")})
	select {
	case err := <-errs:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Ask did not end with the bot's own context")
	}
}

// Close while a bot runs sends nothing: the daemon is going away and the
// caller's task fails by expiry. (The other tests only hit this by whether
// their cleanup beats the bot, so it needs its own deterministic test.)
func TestCloseDuringATaskSendsNothing(t *testing.T) {
	started := make(chan struct{})
	rec := bottest.NewRecorder()
	h, _ := bot.NewHost(bot.Config{Responder: rec, Bot: scripted(func(ctx context.Context, _ bot.Task, _ bot.Session) ([]byte, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})})
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{1}, Content: []byte("x")})
	<-started
	h.Close() // returns once the bot has returned and its task has finished
	if m := rec.Messages([16]byte{1}); len(m) != 0 {
		t.Fatal(m)
	}
}

// The slot of a bot that ignored its context comes back once it returns.
func TestAbandonedBotFreesItsSlot(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	rec := bottest.NewRecorder()
	h, _ := bot.NewHost(bot.Config{Responder: rec, MaxRunning: 1, MaxQueued: 1, Grace: 20 * time.Millisecond,
		Bot: scripted(func(_ context.Context, tk bot.Task, _ bot.Session) ([]byte, error) {
			if tk.ID == ([16]byte{1}) {
				close(started)
				<-release
				return nil, nil
			}
			return []byte("ok"), nil
		})})
	defer h.Close()
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{1}, Content: []byte("x"), Expiry: time.Now().Add(30 * time.Millisecond)})
	<-started
	final(t, rec, 1)
	close(release)
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: [16]byte{2}, Content: []byte("y")})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if m := rec.Wait(ctx, [16]byte{2}, 1); len(m) != 1 || m[0].Type != envelope.TypeResult {
		t.Fatalf("%v", m)
	}
}
