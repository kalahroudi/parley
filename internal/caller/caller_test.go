// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package caller

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/outbox"
	"github.com/kalahroudi/parley/internal/pipeline"
	"github.com/kalahroudi/parley/internal/revocation"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeNode is the pipeline as the caller interface sees it.
type fakeNode struct {
	mu        sync.Mutex
	n         uint16
	submitErr error
	submitted []pipeline.Request
	done      map[[16]byte]chan struct{}
	status    map[[16]byte]outbox.Status
	abandon   error
	follow    error
	followed  []envelope.Type
	followed1 []string
}

func newNode() *fakeNode {
	return &fakeNode{done: map[[16]byte]chan struct{}{}, status: map[[16]byte]outbox.Status{}}
}

func (f *fakeNode) Submit(r pipeline.Request) ([16]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.submitErr != nil {
		return [16]byte{}, f.submitErr
	}
	f.n++
	id := [16]byte{byte(f.n), byte(f.n >> 8)}
	f.submitted = append(f.submitted, r)
	f.done[id] = make(chan struct{})
	f.status[id] = outbox.Status{State: outbox.Waiting}
	return id, nil
}
func (f *fakeNode) Done(id [16]byte) <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.done[id]
}
func (f *fakeNode) Status(id [16]byte) (outbox.Status, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.status[id]
	return s, ok
}
func (f *fakeNode) Abandon(id [16]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.abandon == nil && f.status[id].State != outbox.Waiting {
		return outbox.ErrAlreadySent
	}
	if f.abandon == nil {
		f.status[id] = outbox.Status{State: outbox.Canceled}
		close(f.done[id])
	}
	return f.abandon
}
func (f *fakeNode) Follow(_ context.Context, _ [16]byte, typ envelope.Type, content []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.followed, f.followed1 = append(f.followed, typ), append(f.followed1, string(content))
	return f.follow
}

// finish ends sending the way the outbox would.
func (f *fakeNode) finish(id [16]byte, st outbox.Status) {
	f.mu.Lock()
	f.status[id] = st
	close(f.done[id])
	f.mu.Unlock()
}

type rig struct {
	t   *testing.T
	s   *Service
	n   *fakeNode
	clk *clock
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, n: newNode(), clk: &clock{t: time.Unix(1_700_000_000, 0)}}
	r.s = New(Config{Node: func() (Node, error) { return r.n, nil }, Now: r.clk.now,
		Find: func(_ context.Context, q Query) (*Page, error) {
			return &Page{Agents: []Agent{{ID: "dev-1:ab", Name: q.Text}}}, nil
		}})
	t.Cleanup(r.s.Close)
	return r
}

func code(err error) string {
	var re *localsock.RPCError
	if errors.As(err, &re) {
		return re.Code
	}
	return fmt.Sprint("not an rpc error: ", err)
}

func (r *rig) send(agent, text string) View {
	r.t.Helper()
	v, err := r.s.Send(context.Background(), SendParams{Agent: agent, Text: text})
	if err != nil {
		r.t.Fatalf("send: %v", err)
	}
	return v
}

func id16(v View) [16]byte { id, _ := parseID(v.ID); return id }

func (r *rig) get(v View, wait int64) View {
	r.t.Helper()
	g, err := r.s.Get(context.Background(), GetParams{TaskID: v.ID, WaitSeconds: wait})
	if err != nil {
		r.t.Fatalf("get: %v", err)
	}
	return g
}

// sent ends sending successfully and waits until the service has noticed.
func (r *rig) sent(v View) {
	r.t.Helper()
	r.n.finish(id16(v), outbox.Status{State: outbox.Sent})
	for i := 0; r.get(v, 0).Waiting; i++ {
		if i > 400 {
			r.t.Fatal("the service never noticed the task was sent")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitState(t *testing.T, r *rig, v View, state string) View {
	t.Helper()
	for i := 0; i < 400; i++ {
		if g := r.get(v, 0); g.State == state {
			return g
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task never reached %s (now %s)", state, r.get(v, 0).State)
	return View{}
}

func TestSendGoesToTheDeviceOfACardIdAndStartsSubmitted(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2:abcdef", "hello")
	if v.State != Submitted || !v.Waiting || v.Target != "dev-2" || v.Content != "" || len(v.ID) != 32 {
		t.Fatalf("%+v", v)
	}
	if got := r.n.submitted[0]; got.Target != "dev-2" || string(got.Content) != "hello" || !got.Expiry.Equal(r.clk.now().Add(DefaultExpiry)) {
		t.Fatalf("%+v", got)
	}
	// A bare device id is accepted too, and an explicit expiry is used.
	v2, err := r.s.Send(context.Background(), SendParams{Agent: "dev-3", Text: "x", ExpirySeconds: 60})
	if err != nil || v2.Target != "dev-3" || !r.n.submitted[1].Expiry.Equal(r.clk.now().Add(time.Minute)) {
		t.Fatalf("%+v %v", v2, err)
	}
}

func TestSendRefusesBadRequests(t *testing.T) {
	r := newRig(t)
	for name, p := range map[string]SendParams{
		"nothing to send to":     {Text: "x"},
		"both agent and task":    {Agent: "dev-2", TaskID: strings.Repeat("a", 32), Text: "x"},
		"bad device id":          {Agent: "dev 2", Text: "x"},
		"empty device id":        {Agent: ":ab", Text: "x"},
		"negative expiry":        {Agent: "dev-2", Text: "x", ExpirySeconds: -1},
		"expiry too short":       {Agent: "dev-2", Text: "x", ExpirySeconds: 1},
		"expiry beyond a day":    {Agent: "dev-2", Text: "x", ExpirySeconds: 86401},
		"expiry on a reply":      {TaskID: strings.Repeat("a", 32), Text: "x", ExpirySeconds: 60},
		"reply to a bad task id": {TaskID: "xyz", Text: "x"},
	} {
		if _, err := r.s.Send(context.Background(), p); code(err) != CodeBadParams {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := r.s.Send(context.Background(), SendParams{Agent: "dev-2", Text: strings.Repeat("a", MaxText+1)}); code(err) != CodeTooLarge {
		t.Errorf("too large: %v", err)
	}
	if len(r.n.submitted) != 0 {
		t.Error("a refused request reached the pipeline")
	}
}

func TestSendNeedsAnEnrolledDevice(t *testing.T) {
	r := newRig(t)
	r.s.cfg.Node = func() (Node, error) { return nil, errors.New("not enrolled: secret detail") }
	_, err := r.s.Send(context.Background(), SendParams{Agent: "dev-2", Text: "x"})
	if code(err) != CodeNotReady {
		t.Fatal(err)
	}
	if _, err := r.s.Cancel(context.Background(), CancelParams{TaskID: strings.Repeat("a", 32)}); code(err) != CodeNotFound {
		t.Fatal(err)
	}
}

func TestSubmitErrorsBecomeFixedCodes(t *testing.T) {
	r := newRig(t)
	for err, want := range map[error]string{
		pipeline.ErrBusy:                       CodeBusy,
		outbox.ErrFull:                         CodeBusy,
		outbox.ErrInvalid:                      CodeBadParams,
		outbox.ErrExpired:                      CodeBadParams,
		outbox.ErrTargetFull:                   CodeBusy,
		pipeline.ErrUnknown:                    CodeNotFound,
		pipeline.ErrState:                      CodeWrongState,
		pipeline.ErrNoKey:                      CodeNoKey,
		pipeline.ErrNotReady:                   CodeNotReady,
		revocation.ErrStale:                    CodeNotReady,
		revocation.ErrRevoked:                  CodeNotReady,
		pipeline.ErrPeer:                       CodeNotAllowed,
		pipeline.ErrNotPermitted:               CodeNotAllowed,
		errors.New("gateway said SECRET-TEXT"): CodeInternal,
	} {
		r.n.submitErr = err
		_, got := r.s.Send(context.Background(), SendParams{Agent: "dev-2", Text: "x"})
		if code(got) != want || strings.Contains(got.Error(), "SECRET") {
			t.Errorf("%v: %v", err, got)
		}
	}
	if len(r.s.tasks) != 0 {
		t.Error("a failed submit left a record")
	}
}

func TestResultFlowAndUntrustedMarking(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "work")
	id := id16(v)
	r.n.finish(id, outbox.Status{State: outbox.Sent})
	// Sent: the target has it; still SUBMITTED, no longer waiting.
	for i := 0; r.get(v, 0).Waiting && i < 400; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if g := r.get(v, 0); g.State != Submitted || g.Waiting {
		t.Fatalf("%+v", g)
	}
	r.s.Update(pipeline.Update{Type: envelope.TypeStatus, TaskID: id, Content: []byte("halfway")})
	g := r.get(v, 0)
	if g.State != Working || g.Content != "halfway" || g.Kind != KindStatus || !g.Untrusted {
		t.Fatalf("%+v", g)
	}
	buf := []byte("the answer")
	r.s.Update(pipeline.Update{Type: envelope.TypeResult, TaskID: id, Content: buf})
	clear(buf) // the pipeline clears its buffer after the callback
	g = r.get(v, 0)
	if g.State != Completed || g.Content != "the answer" || g.Kind != KindResult || !g.Untrusted {
		t.Fatalf("%+v", g)
	}
	// A final state is final: a late message changes nothing.
	r.s.Update(pipeline.Update{Type: envelope.TypeError, TaskID: id, Content: []byte("late")})
	if g := r.get(v, 0); g.State != Completed || g.Content != "the answer" {
		t.Fatalf("%+v", g)
	}
	// An update for a task we did not send is dropped.
	r.s.Update(pipeline.Update{Type: envelope.TypeResult, TaskID: [16]byte{99}})
}

func TestUpdateKinds(t *testing.T) {
	for name, tc := range map[string]struct {
		u     pipeline.Update
		cxl   bool
		state string
		kind  string
	}{
		"error":                   {pipeline.Update{Type: envelope.TypeError, Content: []byte("boom")}, false, Failed, KindError},
		"question":                {pipeline.Update{Type: envelope.TypeInputRequired, Content: []byte("which?")}, false, InputRequired, KindQuestion},
		"canceled by the target":  {pipeline.Update{Type: envelope.TypeCancel}, false, Canceled, ""},
		"expired":                 {pipeline.Update{Type: envelope.TypeError, Expired: true}, false, Failed, ""},
		"cancel not acknowledged": {pipeline.Update{Type: envelope.TypeError, Expired: true}, true, Canceled, ""},
	} {
		r := newRig(t)
		v := r.send("dev-2", "x")
		if tc.cxl {
			r.sent(v)
			if _, err := r.s.Cancel(context.Background(), CancelParams{TaskID: v.ID}); err != nil {
				t.Fatal(name, err)
			}
		}
		tc.u.TaskID = id16(v)
		r.s.Update(tc.u)
		g := r.get(v, 0)
		if g.State != tc.state || g.Kind != tc.kind || (tc.u.Expired && g.Reason != ReasonExpired) {
			t.Errorf("%s: %+v", name, g)
		}
	}
}

func TestEveryFailureHasAStateAndAFixedReason(t *testing.T) {
	for _, tc := range []struct {
		err           error
		state, reason string
	}{
		{outbox.ErrRecipientOffline, Failed, ReasonOffline},
		{fmt.Errorf("%w: x", outbox.ErrGone), Failed, ReasonGone},
		{pipeline.ErrNotPermitted, Rejected, ReasonNotAllowed},
		{pipeline.ErrPeer, Rejected, ReasonNotAllowed},
		{pipeline.ErrRefused, Rejected, ReasonRefused},
		{pipeline.ErrPrekey, Rejected, ReasonRefused},
		{pipeline.ErrBusy, Rejected, ReasonBusy},
		{outbox.ErrFull, Rejected, ReasonBusy},
		{outbox.ErrTargetFull, Rejected, ReasonBusy},
		{pipeline.ErrNotReady, Failed, ReasonNotReady},
		{revocation.ErrNoList, Failed, ReasonNotReady},
		{revocation.ErrStale, Failed, ReasonNotReady},
		{revocation.ErrRevoked, Failed, ReasonNotReady},
		{outbox.ErrExpired, Failed, ReasonExpired},
		{errors.New("anything else, SECRET"), Failed, ReasonSendFailed},
		{nil, Failed, ReasonSendFailed},
	} {
		r := newRig(t)
		v := r.send("dev-2", "x")
		r.n.finish(id16(v), outbox.Status{State: outbox.Failed, Err: tc.err})
		g := waitState(t, r, v, tc.state)
		if g.Reason != tc.reason || g.Waiting {
			t.Errorf("%v: %+v", tc.err, g)
		}
	}
}

func TestACanceledOutboxTaskIsCanceled(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	r.n.finish(id16(v), outbox.Status{State: outbox.Canceled})
	waitState(t, r, v, Canceled)
}

func TestGetWaitsForAFinalStateOrAQuestion(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	id := id16(v)
	got := make(chan View, 1)
	go func() { got <- r.get(v, 10) }()
	time.Sleep(20 * time.Millisecond)
	r.s.Update(pipeline.Update{Type: envelope.TypeStatus, TaskID: id, Content: []byte("working")})
	select {
	case g := <-got:
		t.Fatalf("returned on a status message: %+v", g)
	case <-time.After(50 * time.Millisecond):
	}
	r.s.Update(pipeline.Update{Type: envelope.TypeInputRequired, TaskID: id, Content: []byte("which one?")})
	select {
	case g := <-got:
		if g.State != InputRequired || g.Content != "which one?" {
			t.Fatalf("%+v", g)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not return on a question")
	}
}

func TestGetReturnsWhatThereIsWhenTheWaitEnds(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	start := time.Now()
	g, err := r.s.Get(context.Background(), GetParams{TaskID: v.ID, WaitSeconds: 1})
	if err != nil || g.State != Submitted || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("%+v %v after %v", g, err, time.Since(start))
	}
}

func TestGetIsBoundedAndStopsWithItsContextOrTheService(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	if _, err := r.s.Get(context.Background(), GetParams{TaskID: "zz"}); code(err) != CodeBadParams {
		t.Error(err)
	}
	if _, err := r.s.Get(context.Background(), GetParams{TaskID: v.ID, WaitSeconds: -1}); code(err) != CodeBadParams {
		t.Error(err)
	}
	if _, err := r.s.Get(context.Background(), GetParams{TaskID: strings.Repeat("0", 32)}); code(err) != CodeNotFound {
		t.Error(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	res := make(chan error, 1)
	go func() { _, err := r.s.Get(ctx, GetParams{TaskID: v.ID, WaitSeconds: 1000}); res <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-res; code(err) != CodeInternal {
		t.Errorf("canceled wait: %v", err)
	}
	go func() {
		_, err := r.s.Get(context.Background(), GetParams{TaskID: v.ID, WaitSeconds: 1000})
		res <- err
	}()
	time.Sleep(20 * time.Millisecond)
	r.s.Close()
	if err := <-res; code(err) != CodeNotReady {
		t.Errorf("closed: %v", err)
	}
	r.s.Close() // twice is fine
	if _, err := r.s.Get(context.Background(), GetParams{TaskID: v.ID}); code(err) != CodeNotFound {
		t.Errorf("a closed service forgets its tasks: %v", err)
	}
}

func TestMaxWaitIsEnforced(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	r.s.Update(pipeline.Update{Type: envelope.TypeResult, TaskID: id16(v), Content: []byte("r")})
	// Final already: returns at once whatever the wait asked for.
	start := time.Now()
	if g, err := r.s.Get(context.Background(), GetParams{TaskID: v.ID, WaitSeconds: 1 << 40}); err != nil || g.State != Completed || time.Since(start) > time.Second {
		t.Fatalf("%+v %v", g, err)
	}
}

func TestContentIsClippedAndMadeValidUTF8(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	big := append([]byte("ok\xff"), make([]byte, MaxContentView)...)
	r.s.Update(pipeline.Update{Type: envelope.TypeResult, TaskID: id16(v), Content: big})
	g := r.get(v, 0)
	if !g.Truncated || len(g.Content) > MaxContentView+4 || !strings.HasPrefix(g.Content, "ok�") {
		t.Fatalf("truncated=%v len=%d prefix=%q", g.Truncated, len(g.Content), g.Content[:6])
	}
	if _, err := json.Marshal(g); err != nil {
		t.Fatal(err)
	}
}

func TestReplyToAQuestion(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	r.s.Update(pipeline.Update{Type: envelope.TypeInputRequired, TaskID: id16(v), Content: []byte("which?")})
	got, err := r.s.Send(context.Background(), SendParams{TaskID: v.ID, Text: "this one"})
	if err != nil || got.State != Working || got.Content != "" {
		t.Fatalf("%+v %v", got, err)
	}
	if r.n.followed[0] != envelope.TypeReply || r.n.followed1[0] != "this one" {
		t.Fatalf("%v %v", r.n.followed, r.n.followed1)
	}
	if g := r.get(v, 0); g.Content != "" {
		t.Errorf("the answered question is still held: %+v", g)
	}
	// An unknown task, and errors from the pipeline.
	if _, err := r.s.Send(context.Background(), SendParams{TaskID: strings.Repeat("0", 32), Text: "x"}); code(err) != CodeNotFound {
		t.Error(err)
	}
	r.n.follow = pipeline.ErrState
	if _, err := r.s.Send(context.Background(), SendParams{TaskID: v.ID, Text: "again"}); code(err) != CodeWrongState {
		t.Error(err)
	}
	// A reply that raced with the end of the task does not reopen it.
	r.n.follow = nil
	r.s.Update(pipeline.Update{Type: envelope.TypeResult, TaskID: id16(v), Content: []byte("done")})
	if got, err := r.s.Send(context.Background(), SendParams{TaskID: v.ID, Text: "late"}); err != nil || got.State != Completed {
		t.Errorf("%+v %v", got, err)
	}
}

func TestCancelBeforeSending(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	c, err := r.s.Cancel(context.Background(), CancelParams{TaskID: v.ID})
	if err != nil || c.State != Canceled || c.Waiting {
		t.Fatalf("%+v %v", c, err)
	}
	if len(r.n.followed) != 0 {
		t.Error("a task that was never sent got a CANCEL message")
	}
	if _, err := r.s.Cancel(context.Background(), CancelParams{TaskID: v.ID}); code(err) != CodeWrongState {
		t.Errorf("canceling twice: %v", err)
	}
}

func TestCancelWhileSendingAndAfterSent(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	r.n.abandon = outbox.ErrSending
	if _, err := r.s.Cancel(context.Background(), CancelParams{TaskID: v.ID}); code(err) != CodeSending {
		t.Fatal(err)
	}
	r.n.abandon = errors.New("odd")
	if _, err := r.s.Cancel(context.Background(), CancelParams{TaskID: v.ID}); code(err) != CodeInternal {
		t.Fatal(err)
	}
	// It was sent between our look and the cancel: a signed CANCEL goes instead.
	r.n.abandon = outbox.ErrAlreadySent
	c, err := r.s.Cancel(context.Background(), CancelParams{TaskID: v.ID})
	if err != nil || !c.Cancel || len(r.n.followed) != 1 || r.n.followed[0] != envelope.TypeCancel {
		t.Fatalf("%+v %v %v", c, err, r.n.followed)
	}
	// The target acknowledges.
	r.s.Update(pipeline.Update{Type: envelope.TypeCancel, TaskID: id16(v)})
	if g := r.get(v, 0); g.State != Canceled || g.Cancel {
		t.Fatalf("%+v", g)
	}
}

func TestCancelOfASentTaskNeedsAKeyOrFails(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	r.sent(v)
	r.n.follow = pipeline.ErrNoKey
	if _, err := r.s.Cancel(context.Background(), CancelParams{TaskID: v.ID}); code(err) != CodeNoKey {
		t.Fatal(err)
	}
	if g := r.get(v, 0); g.Cancel {
		t.Error("a cancel that was not sent is shown as requested")
	}
	if _, err := r.s.Cancel(context.Background(), CancelParams{TaskID: "bad"}); code(err) != CodeBadParams {
		t.Fatal(err)
	}
}

func TestListIsNewestFirstPagedAndFiltered(t *testing.T) {
	r := newRig(t)
	var vs []View
	for i := 0; i < 7; i++ {
		vs = append(vs, r.send("dev-2", "x"))
	}
	r.s.Update(pipeline.Update{Type: envelope.TypeResult, TaskID: id16(vs[2]), Content: []byte("SECRET-RESULT")})
	var seen []string
	cursor := ""
	for pages := 0; ; pages++ {
		res, err := r.s.List(context.Background(), ListParams{Limit: 3, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range res.Tasks {
			if v.Content != "" || v.Untrusted {
				t.Fatalf("a list carries content: %+v", v)
			}
			seen = append(seen, v.ID)
		}
		if cursor = res.NextCursor; cursor == "" {
			if pages != 2 {
				t.Fatalf("%d pages", pages+1)
			}
			break
		}
	}
	if len(seen) != 7 || seen[0] != vs[6].ID || seen[6] != vs[0].ID {
		t.Fatalf("order: %v", seen)
	}
	res, _ := r.s.List(context.Background(), ListParams{State: Completed})
	if len(res.Tasks) != 1 || res.Tasks[0].ID != vs[2].ID || res.NextCursor != "" {
		t.Fatalf("%+v", res)
	}
	if res, _ := r.s.List(context.Background(), ListParams{State: Rejected}); res.Tasks == nil || len(res.Tasks) != 0 {
		t.Fatalf("an empty page must be [] not null: %+v", res)
	}
	// A page of exactly the limit has no next page.
	if res, _ := r.s.List(context.Background(), ListParams{Limit: 7}); len(res.Tasks) != 7 || res.NextCursor != "" {
		t.Fatalf("%d %q", len(res.Tasks), res.NextCursor)
	}
}

func TestListRefusesBadParams(t *testing.T) {
	r := newRig(t)
	for _, p := range []ListParams{{Limit: -1}, {Limit: MaxLimit + 1}, {State: "TASK_STATE_BOGUS"}, {Cursor: "zz"}, {Cursor: "00"}, {Cursor: strings.Repeat("00", 9)}} {
		if _, err := r.s.List(context.Background(), p); code(err) != CodeBadParams {
			t.Errorf("%+v: %v", p, err)
		}
	}
}

func TestSendsAreRateLimitedAndRefill(t *testing.T) {
	r := newRig(t)
	for i := 0; i < SendsPerMinute; i++ {
		r.s.cfg.Node = func() (Node, error) { return r.n, nil }
		if _, err := r.s.Send(context.Background(), SendParams{Agent: "dev-2", Text: "x"}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if _, err := r.s.Send(context.Background(), SendParams{Agent: "dev-2", Text: "x"}); code(err) != CodeRateLimit {
		t.Fatalf("over the limit: %v", err)
	}
	r.clk.add(2 * time.Second) // 30 per minute: one token per two seconds
	if _, err := r.s.Send(context.Background(), SendParams{Agent: "dev-2", Text: "x"}); err != nil {
		t.Fatalf("after a refill: %v", err)
	}
	r.clk.add(-time.Hour) // a clock that steps back does not mint tokens
	if _, err := r.s.Send(context.Background(), SendParams{Agent: "dev-2", Text: "x"}); code(err) != CodeRateLimit {
		t.Fatalf("clock moved back: %v", err)
	}
}

func TestFinishedTasksAreForgottenAndWipedAndLiveOnesAreNotEvicted(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	r.s.Update(pipeline.Update{Type: envelope.TypeResult, TaskID: id16(v), Content: []byte("secret result")})
	r.s.mu.Lock()
	held := r.s.tasks[id16(v)].content
	r.s.mu.Unlock()
	r.clk.add(KeepDone + time.Second)
	r.send("dev-2", "y") // making room drops it
	if _, err := r.s.Get(context.Background(), GetParams{TaskID: v.ID}); code(err) != CodeNotFound {
		t.Fatal(err)
	}
	if strings.Contains(string(held), "secret") {
		t.Error("the dropped record's content was not wiped")
	}

	// At the cap, the oldest finished task goes first; with only live tasks, new ones are refused.
	r = newRig(t)
	for i := 0; i < MaxTasks; i++ {
		r.s.sends = newBucket(1<<20, r.clk.now)
		r.send("dev-2", "x")
	}
	if _, err := r.s.Send(context.Background(), SendParams{Agent: "dev-2", Text: "x"}); code(err) != CodeBusy {
		t.Fatalf("all live: %v", err)
	}
	first, last := id16(View{ID: hex.EncodeToString([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})}), [16]byte{}
	_ = last
	r.clk.add(time.Second)
	r.s.Update(pipeline.Update{Type: envelope.TypeResult, TaskID: first, Content: []byte("r")})
	r.clk.add(time.Second)
	r.s.Update(pipeline.Update{Type: envelope.TypeResult, TaskID: [16]byte{2}, Content: []byte("r")})
	if _, err := r.s.Send(context.Background(), SendParams{Agent: "dev-2", Text: "x"}); err != nil {
		t.Fatalf("with finished tasks to evict: %v", err)
	}
	if _, ok := r.s.tasks[first]; ok {
		t.Error("the oldest finished task was kept")
	}
	if _, ok := r.s.tasks[[16]byte{2}]; !ok {
		t.Error("a newer finished task was evicted before the oldest")
	}
}

func TestSettleIgnoresAForgottenTask(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	r.s.mu.Lock()
	t0 := r.s.tasks[id16(v)]
	delete(r.s.tasks, id16(v))
	r.s.mu.Unlock()
	r.n.finish(id16(v), outbox.Status{State: outbox.Failed, Err: outbox.ErrGone})
	r.s.settle(r.n, t0) // must not resurrect or panic
	if t0.terminal() {
		t.Error("a forgotten task changed state")
	}
}

func TestWatchStopsWhenTheServiceCloses(t *testing.T) {
	r := newRig(t)
	r.send("dev-2", "x")
	r.s.Close() // the watcher is waiting on Done; it must not leak or touch the wiped record
}

func TestMethodsDecodeStrictly(t *testing.T) {
	r := newRig(t)
	m := r.s.Methods()
	for _, name := range []string{"find_agents", "send_task", "get_task", "cancel_task", "list_tasks"} {
		if m[name] == nil {
			t.Fatalf("no method %s", name)
		}
	}
	call := func(name, params string) (any, error) { return m[name](context.Background(), json.RawMessage(params)) }
	for _, bad := range []struct{ name, params string }{
		{"send_task", `{"agent":"dev-2","text":"x","extra":1}`},
		{"send_task", `{"agent":"dev-2","text":"x"} {"a":1}`},
		{"send_task", `[1]`},
		{"send_task", `{"text":5}`},
		{"get_task", `"id"`},
		{"list_tasks", `{"limit":"5"}`},
	} {
		if _, err := call(bad.name, bad.params); code(err) != CodeBadParams {
			t.Errorf("%s %s: %v", bad.name, bad.params, err)
		}
	}
	res, err := call("send_task", `{"agent":"dev-2","text":"x"}`)
	if err != nil || res.(View).State != Submitted {
		t.Fatalf("%+v %v", res, err)
	}
	if res, err := call("list_tasks", ``); err != nil || len(res.(ListResult).Tasks) != 1 {
		t.Fatalf("no params at all must work: %+v %v", res, err)
	}
}

func TestNewDefaultsToTheRealClock(t *testing.T) {
	s := New(Config{})
	defer s.Close()
	if s.cfg.Now == nil || time.Since(s.cfg.Now()) > time.Minute {
		t.Error("no usable clock")
	}
}

func TestCancelBeforeTheNodeIsReady(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	r.s.cfg.Node = func() (Node, error) { return nil, errors.New("SECRET") }
	_, err := r.s.Cancel(context.Background(), CancelParams{TaskID: v.ID})
	if code(err) != CodeNotReady || strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
}

func TestCloseLeavesNoGoroutinesBehind(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		r := newRig(t)
		for j := 0; j < 5; j++ {
			r.send("dev-2", "x") // each starts a watcher that waits for the outbox
		}
		r.s.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before+1 {
		t.Errorf("%d goroutines left (before: %d)", n, before)
	}
}
