// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/trust"
)

// clock is a fake time source: Sleep advances it at once and records the wait.
type clock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func newClock() *clock { return &clock{now: time.Now().Truncate(time.Second)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *clock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	c.mu.Unlock()
	runtime.Gosched()
	return nil
}

func (c *clock) waits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}

type presenceResult struct {
	online bool
	err    error
}

// script answers Presence from a list, repeating the last answer.
type script struct {
	mu      sync.Mutex
	results []presenceResult
	calls   int
}

func (s *script) presence(ctx context.Context, target string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.results[min(s.calls, len(s.results)-1)]
	s.calls++
	return r.online, r.err
}

func (s *script) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type rateLimited time.Duration

func (r rateLimited) Error() string             { return "rate limited" }
func (r rateLimited) RetryAfter() time.Duration { return time.Duration(r) }

func same(d time.Duration) time.Duration { return d }

func newOutbox(t *testing.T, cfg Config) *Outbox {
	t.Helper()
	if cfg.Send == nil {
		cfg.Send = func(context.Context, Task) error { return nil }
	}
	o, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(o.Close)
	return o
}

func waitDone(t *testing.T, o *Outbox, id string) Status {
	t.Helper()
	select {
	case <-o.Done(id):
	case <-time.After(10 * time.Second):
		t.Fatalf("task %s never finished", id)
	}
	s, ok := o.Status(id)
	if !ok {
		t.Fatalf("task %s unknown", id)
	}
	return s
}

func task(c *clock, id string, in time.Duration) Task {
	return Task{ID: id, Target: "card-" + id, Expiry: c.Now().Add(in)}
}

func ms(d ...int) []time.Duration {
	var out []time.Duration
	for _, v := range d {
		out = append(out, time.Duration(v)*time.Millisecond)
	}
	return out
}

func TestWaitsForTheTargetWithGrowingPollsThenSends(t *testing.T) {
	c := newClock()
	s := &script{results: []presenceResult{{}, {}, {}, {}, {}, {}, {online: true}}}
	var sent []Task
	o := newOutbox(t, Config{Presence: s.presence, Now: c.Now, Sleep: c.Sleep, Jitter: same,
		Send: func(_ context.Context, tk Task) error { sent = append(sent, tk); return nil }})
	tk := task(c, "a", 15*time.Minute)
	if err := o.Submit(tk); err != nil {
		t.Fatal(err)
	}
	if st := waitDone(t, o, "a"); st != (Status{State: Sent}) {
		t.Fatalf("status %+v", st)
	}
	if len(sent) != 1 || sent[0] != tk {
		t.Fatalf("sent %v", sent)
	}
	// 1 s, doubled each time, capped at 15 s.
	want := ms(1000, 2000, 4000, 8000, 15000, 15000)
	if got := c.waits(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("waits %v, want %v", got, want)
	}
}

func TestSendsAtOnceWhenTheTargetIsOnline(t *testing.T) {
	c := newClock()
	o := newOutbox(t, Config{Presence: (&script{results: []presenceResult{{online: true}}}).presence, Now: c.Now, Sleep: c.Sleep})
	if err := o.Submit(task(c, "a", time.Minute)); err != nil {
		t.Fatal(err)
	}
	if st := waitDone(t, o, "a"); st.State != Sent || len(c.waits()) != 0 {
		t.Fatalf("%+v waits %v", st, c.waits())
	}
}

func TestFailsAtExpiryWithoutEverSending(t *testing.T) {
	c := newClock()
	s := &script{results: []presenceResult{{}}}
	o := newOutbox(t, Config{Presence: s.presence, Now: c.Now, Sleep: c.Sleep, Jitter: same, MinPoll: 10 * time.Second, MaxPoll: 10 * time.Second,
		Send: func(context.Context, Task) error { t.Error("sent to an offline target"); return nil }})
	tk := task(c, "a", 25*time.Second)
	if err := o.Submit(tk); err != nil {
		t.Fatal(err)
	}
	st := waitDone(t, o, "a")
	if st.State != Failed || !errors.Is(st.Err, ErrRecipientOffline) {
		t.Fatalf("status %+v", st)
	}
	// 10 s, 10 s, then only the 5 s that are left: it does not sleep past the expiry.
	if got := c.waits(); fmt.Sprint(got) != fmt.Sprint(ms(10000, 10000, 5000)) {
		t.Fatalf("waits %v", got)
	}
	if !c.Now().Equal(tk.Expiry) || s.count() != 3 {
		t.Fatalf("ended at %v (expiry %v) after %d checks", c.Now(), tk.Expiry, s.count())
	}
}

func TestHoldsOffForTheGatewaysRateLimit(t *testing.T) {
	c := newClock()
	wrapped := fmt.Errorf("presence: %w", rateLimited(7*time.Second))
	s := &script{results: []presenceResult{{err: wrapped}, {err: rateLimited(3 * time.Second)}, {online: true}}}
	o := newOutbox(t, Config{Presence: s.presence, Now: c.Now, Sleep: c.Sleep, Jitter: same})
	if err := o.Submit(task(c, "a", time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st := waitDone(t, o, "a"); st.State != Sent {
		t.Fatalf("%+v", st)
	}
	if got := c.waits(); fmt.Sprint(got) != fmt.Sprint([]time.Duration{7 * time.Second, 3 * time.Second}) {
		t.Fatalf("waits %v", got)
	}
}

func TestOtherPresenceErrorsAreRetriedNotFatal(t *testing.T) {
	c := newClock()
	s := &script{results: []presenceResult{{err: errors.New("gateway unreachable")}, {err: errors.New("again")}, {online: true}}}
	o := newOutbox(t, Config{Presence: s.presence, Now: c.Now, Sleep: c.Sleep, Jitter: same})
	if err := o.Submit(task(c, "a", time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st := waitDone(t, o, "a"); st.State != Sent {
		t.Fatalf("%+v", st)
	}
	if got := c.waits(); fmt.Sprint(got) != fmt.Sprint(ms(1000, 2000)) {
		t.Fatalf("waits %v", got)
	}
}

func TestAGoneRecipientFailsAtOnce(t *testing.T) {
	c := newClock()
	gone := fmt.Errorf("%w: card removed", ErrGone)
	o := newOutbox(t, Config{Presence: (&script{results: []presenceResult{{err: gone}}}).presence, Now: c.Now, Sleep: c.Sleep})
	if err := o.Submit(task(c, "a", time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st := waitDone(t, o, "a"); st.State != Failed || !errors.Is(st.Err, ErrGone) || len(c.waits()) != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestASendFailureFailsTheTask(t *testing.T) {
	c := newClock()
	refused := errors.New("not permitted")
	o := newOutbox(t, Config{Presence: (&script{results: []presenceResult{{online: true}}}).presence, Now: c.Now, Sleep: c.Sleep,
		Send: func(context.Context, Task) error { return refused }})
	if err := o.Submit(task(c, "a", time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st := waitDone(t, o, "a"); st.State != Failed || !errors.Is(st.Err, refused) {
		t.Fatalf("%+v", st)
	}
}

func TestATargetThatDropsDuringTheSendKeepsWaiting(t *testing.T) {
	c := newClock()
	var calls int
	o := newOutbox(t, Config{Presence: (&script{results: []presenceResult{{online: true}}}).presence, Now: c.Now, Sleep: c.Sleep, Jitter: same,
		Send: func(context.Context, Task) error {
			calls++
			if calls < 3 {
				return fmt.Errorf("prekey request: %w", ErrOffline)
			}
			return nil
		}})
	if err := o.Submit(task(c, "a", time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st := waitDone(t, o, "a"); st.State != Sent || calls != 3 {
		t.Fatalf("%+v after %d sends", st, calls)
	}
	if got := c.waits(); fmt.Sprint(got) != fmt.Sprint(ms(1000, 2000)) {
		t.Fatalf("waits %v", got)
	}
}

func TestSendingIsVisibleAndCannotBeCanceledHere(t *testing.T) {
	c := newClock()
	in, release := make(chan struct{}), make(chan struct{})
	o := newOutbox(t, Config{Presence: (&script{results: []presenceResult{{online: true}}}).presence, Now: c.Now, Sleep: c.Sleep,
		Send: func(ctx context.Context, tk Task) error {
			if dl, ok := ctx.Deadline(); !ok || !dl.Equal(tk.Expiry) {
				t.Errorf("send deadline %v, want the task expiry", dl)
			}
			close(in)
			<-release
			return nil
		}})
	if err := o.Submit(task(c, "a", time.Hour)); err != nil {
		t.Fatal(err)
	}
	<-in
	if st, _ := o.Status("a"); st.State != Sending {
		t.Fatalf("%+v", st)
	}
	if err := o.Cancel("a"); !errors.Is(err, ErrSending) {
		t.Fatalf("cancel while sending: %v", err)
	}
	close(release)
	waitDone(t, o, "a")
	if err := o.Cancel("a"); !errors.Is(err, ErrAlreadySent) {
		t.Fatalf("cancel after sent: %v", err)
	}
}

func TestCancelWhileWaiting(t *testing.T) {
	c := newClock()
	parked, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	o := newOutbox(t, Config{Presence: (&script{results: []presenceResult{{}}}).presence, Now: c.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			once.Do(func() { close(parked) })
			<-resume
			return nil
		},
		Send: func(context.Context, Task) error { t.Error("sent a canceled task"); return nil }})
	if err := o.Submit(task(c, "a", time.Hour)); err != nil {
		t.Fatal(err)
	}
	<-parked
	if err := o.Cancel("a"); err != nil {
		t.Fatal(err)
	}
	if st := waitDone(t, o, "a"); st != (Status{State: Canceled}) {
		t.Fatalf("%+v", st)
	}
	if err := o.Cancel("a"); err != nil { // canceling twice is fine
		t.Fatal(err)
	}
	if err := o.Cancel("nope"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown: %v", err)
	}
	close(resume) // the goroutine wakes, sees the cancel and ends without sending
	o.Close()
	if st, _ := o.Status("a"); st.State != Canceled {
		t.Fatalf("close changed a canceled task: %+v", st)
	}
	// A failed task can be canceled again too, and stays failed.
	o2 := newOutbox(t, Config{Presence: (&script{results: []presenceResult{{err: ErrGone}}}).presence})
	if err := o2.Submit(task(c, "f", time.Hour)); err != nil {
		t.Fatal(err)
	}
	waitDone(t, o2, "f")
	if err := o2.Cancel("f"); err != nil {
		t.Fatal(err)
	}
	if st, _ := o2.Status("f"); st.State != Failed {
		t.Fatalf("%+v", st)
	}
}

func TestCancelBetweenThePresenceCheckAndTheSend(t *testing.T) {
	c := newClock()
	var o *Outbox
	o = newOutbox(t, Config{Now: c.Now, Sleep: c.Sleep,
		Presence: func(context.Context, string) (bool, error) {
			if err := o.Cancel("a"); err != nil {
				t.Error(err)
			}
			return true, nil
		},
		Send: func(context.Context, Task) error { t.Error("sent a canceled task"); return nil }})
	if err := o.Submit(task(c, "a", time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st := waitDone(t, o, "a"); st.State != Canceled {
		t.Fatalf("%+v", st)
	}
	o.Close() // the goroutine has ended without sending
}

func TestCloseFailsWhatIsWaiting(t *testing.T) {
	c := newClock()
	inPresence, inSend, inSleep := make(chan struct{}), make(chan struct{}), make(chan struct{})
	o := newOutbox(t, Config{Now: c.Now, MaxWaiting: 10,
		Sleep: func(ctx context.Context, d time.Duration) error {
			close(inSleep)
			<-ctx.Done()
			return ctx.Err()
		},
		Presence: func(ctx context.Context, target string) (bool, error) {
			switch target {
			case "card-presence":
				close(inPresence)
				<-ctx.Done()
				return false, ctx.Err()
			case "card-send":
				return true, nil
			}
			return false, nil // "card-sleep": offline, in the real sleep
		},
		Send: func(ctx context.Context, tk Task) error {
			close(inSend)
			<-ctx.Done()
			return ctx.Err()
		}})
	for _, id := range []string{"sleep", "presence", "send"} {
		if err := o.Submit(task(c, id, time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	<-inPresence
	<-inSend
	<-inSleep
	o.Close()
	for _, id := range []string{"sleep", "presence", "send"} {
		if st, _ := o.Status(id); st.State != Failed || !errors.Is(st.Err, ErrClosed) {
			t.Fatalf("%s: %+v", id, st)
		}
	}
	if err := o.Submit(task(c, "late", time.Hour)); !errors.Is(err, ErrClosed) {
		t.Fatalf("submit after close: %v", err)
	}
}

func TestRealClockAndDefaults(t *testing.T) {
	o, err := New(Config{
		Presence: (&script{results: []presenceResult{{}, {}, {online: true}}}).presence,
		Send:     func(context.Context, Task) error { return nil },
		MinPoll:  time.Millisecond, MaxPoll: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err := o.Submit(Task{ID: "a", Target: "x", Expiry: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if st := waitDone(t, o, "a"); st.State != Sent {
		t.Fatalf("%+v", st)
	}
	// And the real expiry.
	o2, _ := New(Config{Presence: (&script{results: []presenceResult{{}}}).presence, Send: func(context.Context, Task) error { return nil }, MinPoll: time.Millisecond, MaxPoll: 2 * time.Millisecond})
	defer o2.Close()
	if err := o2.Submit(Task{ID: "b", Target: "x", Expiry: time.Now().Add(40 * time.Millisecond)}); err != nil {
		t.Fatal(err)
	}
	if st := waitDone(t, o2, "b"); !errors.Is(st.Err, ErrRecipientOffline) {
		t.Fatalf("%+v", st)
	}
}

func TestRealSleep(t *testing.T) {
	if err := sleep(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

func TestConfigDefaults(t *testing.T) {
	ok := func(context.Context, string) (bool, error) { return false, nil }
	send := func(context.Context, Task) error { return nil }
	if _, err := New(Config{Send: send}); err == nil {
		t.Fatal("no Presence")
	}
	if _, err := New(Config{Presence: ok}); err == nil {
		t.Fatal("no Send")
	}
	o, _ := New(Config{Presence: ok, Send: send})
	defer o.Close()
	c := o.cfg
	if c.MaxWaiting != DefaultMaxWaiting || c.MaxFinished != DefaultMaxFinished || c.KeepDone != DefaultKeepDone || c.MinPoll != DefaultMinPoll || c.MaxPoll != DefaultMaxPoll {
		t.Fatalf("defaults %+v", c)
	}
	o2, _ := New(Config{Presence: ok, Send: send, MinPoll: time.Minute, MaxPoll: time.Second})
	defer o2.Close()
	if o2.cfg.MinPoll != time.Minute || o2.cfg.MaxPoll != time.Minute {
		t.Fatalf("a max below the min is raised to it: %+v", o2.cfg)
	}
	o3, _ := New(Config{Presence: ok, Send: send, MinPoll: time.Second, MaxPoll: 3 * time.Second})
	defer o3.Close()
	if o3.cfg.MaxPoll != 3*time.Second {
		t.Fatalf("explicit max kept: %+v", o3.cfg)
	}
}

func TestSubmitChecks(t *testing.T) {
	c := newClock()
	hold := make(chan struct{})
	defer close(hold)
	o := newOutbox(t, Config{Presence: (&script{results: []presenceResult{{}}}).presence, Now: c.Now, MaxWaiting: 2,
		Sleep: func(ctx context.Context, d time.Duration) error { <-hold; return ctx.Err() }})
	long := make([]byte, 65)
	for i := range long {
		long[i] = 'x'
	}
	for name, tk := range map[string]Task{
		"no id":         {Target: "x", Expiry: c.Now().Add(time.Hour)},
		"id too long":   {ID: string(long), Target: "x", Expiry: c.Now().Add(time.Hour)},
		"no target":     {ID: "a", Expiry: c.Now().Add(time.Hour)},
		"over 24 hours": {ID: "a", Target: "x", Expiry: c.Now().Add(MaxExpiry + time.Second)},
	} {
		if err := o.Submit(tk); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := o.Submit(Task{ID: "a", Target: "x", Expiry: c.Now()}); !errors.Is(err, ErrExpired) {
		t.Errorf("expired: %v", err)
	}
	if err := o.Submit(Task{ID: "a", Target: "x", Expiry: c.Now().Add(MaxExpiry)}); err != nil { // exactly 24 h is allowed
		t.Fatal(err)
	}
	if err := o.Submit(task(c, "a", time.Hour)); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate: %v", err)
	}
	if err := o.Submit(task(c, "b", time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := o.Submit(task(c, "c", time.Hour)); !errors.Is(err, ErrFull) {
		t.Errorf("full: %v", err)
	}
	if err := o.Cancel("a"); err != nil { // a freed slot is reusable
		t.Fatal(err)
	}
	if err := o.Submit(task(c, "c", time.Hour)); err != nil {
		t.Errorf("after a slot freed: %v", err)
	}
}

func TestStatesUseTheGatewaysVocabulary(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "gateway", "src", "a2a.ts"))
	if err != nil {
		t.Fatal(err)
	}
	for st, want := range map[State]string{Waiting: "TASK_STATE_SUBMITTED", Sending: "TASK_STATE_SUBMITTED", Failed: "TASK_STATE_FAILED", Canceled: "TASK_STATE_CANCELED", Sent: ""} {
		if got := (Status{State: st}).A2AState(); got != want {
			t.Errorf("state %d: %q, want %q", st, got, want)
		}
		if want != "" && !strings.Contains(string(src), `"`+want+`"`) {
			t.Errorf("gateway/src/a2a.ts no longer names %s", want)
		}
	}
}

// Exactly once: many tasks, some canceled, some whose target drops mid-send, all
// racing. Each task is sent (Send returned nil) at most once, never concurrently
// with itself, and never after it was canceled or failed.
func TestEachTaskIsSentAtMostOnceUnderRaces(t *testing.T) {
	c := newClock()
	var mu sync.Mutex
	sent := map[string]int{}
	inFlight := map[string]bool{}
	drops := map[string]int{}
	o := newOutbox(t, Config{Now: c.Now, Sleep: c.Sleep, Jitter: same, MaxWaiting: 200,
		Presence: func(_ context.Context, target string) (bool, error) { return target != "card-t7", nil },
		Send: func(_ context.Context, tk Task) error {
			mu.Lock()
			if inFlight[tk.ID] {
				t.Errorf("%s sent concurrently", tk.ID)
			}
			inFlight[tk.ID] = true
			mu.Unlock()
			runtime.Gosched() // give a second sender of the same task every chance to overlap
			mu.Lock()
			defer mu.Unlock()
			inFlight[tk.ID] = false
			if drops[tk.ID] < 2 && tk.ID[len(tk.ID)-1]%2 == 0 {
				drops[tk.ID]++
				return ErrOffline
			}
			sent[tk.ID]++
			return nil
		}})
	const n = 100
	for i := 0; i < n; i++ {
		if err := o.Submit(task(c, fmt.Sprintf("t%d", i), time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i += 3 {
		wg.Add(1)
		go func(id string) { defer wg.Done(); _ = o.Cancel(id) }(fmt.Sprintf("t%d", i))
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("t%d", i)
		if id == "t7" {
			if err := o.Cancel(id); err != nil { // never online: it is still waiting
				t.Fatal(err)
			}
		}
		st := waitDone(t, o, id)
		mu.Lock()
		n := sent[id]
		mu.Unlock()
		if n > 1 || (st.State == Sent) != (n == 1) {
			t.Fatalf("%s: state %+v sent %d times", id, st, n)
		}
		if st.State == Canceled && n != 0 {
			t.Fatalf("%s sent and canceled", id)
		}
	}
}

func TestAnIdOf64BytesIsAccepted(t *testing.T) {
	c := newClock()
	o := newOutbox(t, Config{Presence: (&script{results: []presenceResult{{online: true}}}).presence, Now: c.Now, Sleep: c.Sleep})
	if err := o.Submit(task(c, strings.Repeat("x", 64), time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func TestFinishedTasksAreRemembered_ThenForgotten(t *testing.T) {
	c := newClock()
	o := newOutbox(t, Config{Presence: (&script{results: []presenceResult{{online: true}}}).presence, Now: c.Now, Sleep: c.Sleep, KeepDone: time.Minute, MaxFinished: 3})
	run := func(id string) {
		t.Helper()
		if err := o.Submit(task(c, id, time.Hour)); err != nil {
			t.Fatal(err)
		}
		waitDone(t, o, id)
		c.advance(time.Second)
	}
	run("a")
	run("b")
	run("c")
	for _, id := range []string{"a", "b", "c"} {
		if _, ok := o.Status(id); !ok {
			t.Fatalf("%s forgotten too early", id)
		}
	}
	run("d") // three finished: the oldest goes to make room
	if _, ok := o.Status("a"); ok {
		t.Fatal("a kept past the cap")
	}
	for _, id := range []string{"b", "c", "d"} {
		if _, ok := o.Status(id); !ok {
			t.Fatalf("%s evicted", id)
		}
	}
	c.advance(57 * time.Second) // now b (finished at 1 s) is a minute old, c (2 s) is 59 s
	run("e")                    // b has aged out; c, d, e remain
	if _, ok := o.Status("b"); ok {
		t.Fatal("b kept past KeepDone")
	}
	if _, ok := o.Status("c"); !ok {
		t.Fatal("c dropped early")
	}
	select {
	case <-o.Done("b"):
	default:
		t.Fatal("Done for an unknown task must be closed")
	}
	if _, ok := o.Status("never"); ok {
		t.Fatal("unknown task")
	}
	// The same id can be used again once forgotten.
	if err := o.Submit(task(c, "b", time.Hour)); err != nil {
		t.Fatal(err)
	}
	waitDone(t, o, "b")
}

func TestAFinishedTaskIsForgottenExactlyAtKeepDone(t *testing.T) {
	c := newClock()
	o := newOutbox(t, Config{Presence: (&script{results: []presenceResult{{online: true}}}).presence, Now: c.Now, Sleep: c.Sleep, KeepDone: time.Minute})
	for _, id := range []string{"a", "b"} {
		if err := o.Submit(task(c, id, time.Hour)); err != nil {
			t.Fatal(err)
		}
		waitDone(t, o, id)
	}
	c.advance(time.Minute - time.Nanosecond)
	if err := o.Submit(task(c, "c", time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := o.Status("a"); !ok {
		t.Fatal("forgotten a nanosecond early")
	}
	c.advance(time.Nanosecond)
	if err := o.Submit(task(c, "d", time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := o.Status("a"); ok {
		t.Fatal("kept at KeepDone")
	}
}

func TestJitterStaysWithinAQuarter(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := 8 * time.Second
		if j := jitter(d); j < d || j > d+d/4 {
			t.Fatalf("jitter(%v) = %v", d, j)
		}
	}
	if d := jitter(time.Nanosecond); d != time.Nanosecond {
		t.Fatalf("jitter of one nanosecond: %v", d)
	}
}

func TestTrustPresence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct{ ID string }
		_ = jsonDecode(r, &b)
		switch b.ID {
		case "up":
			w.Write([]byte(`{"online":true}`))
		case "limited":
			w.Header().Set("Retry-After", "4")
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			http.Error(w, "gone", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	p := TrustPresence(&trust.Client{BaseURL: srv.URL})
	ctx := context.Background()
	if on, err := p(ctx, "up"); err != nil || !on {
		t.Fatalf("%v %v", on, err)
	}
	if _, err := p(ctx, "hidden"); !errors.Is(err, ErrGone) {
		t.Fatalf("not found should be ErrGone: %v", err)
	}
	_, err := p(ctx, "limited")
	if d, ok := retryAfter(err); !ok || d != 4*time.Second || errors.Is(err, ErrGone) {
		t.Fatalf("rate limit passed through: %v %v %v", d, ok, err)
	}
	if _, ok := retryAfter(errors.New("plain")); ok {
		t.Fatal("a plain error has no retry-after")
	}
}

func jsonDecode(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }
