// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package caller

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/outbox"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// Constant expressions have no statement for a mutant to be covered by; the
// limits are pinned here.
func TestLimitsArePinned(t *testing.T) {
	if MaxText != 32<<10 || MaxContentView != 32<<10 || KeepDone != 15*time.Minute || DefaultExpiry != 15*time.Minute ||
		MinExpiry != 5*time.Second || MaxWait != 20*time.Second || dirTimeout != 15*time.Second || dirTokenSlack != 30*time.Second ||
		maxDirReply != 512<<10 || maxCursor != 1600 || MaxLimit != 100 || DefaultLimit != 25 || MaxTasks != 256 {
		t.Fatal("a limit changed")
	}
}

func (r *rig) unlimited() {
	r.s.sends = newBucket(1<<20, r.clk.now)
	r.s.finds = newBucket(1<<20, r.clk.now)
}

func TestSendLimitsAreExact(t *testing.T) {
	r := newRig(t)
	r.unlimited()
	send := func(p SendParams) error { _, err := r.s.Send(context.Background(), p); return err }
	if err := send(SendParams{Agent: "dev-2", Text: strings.Repeat("a", MaxText)}); err != nil {
		t.Errorf("text at the limit: %v", err)
	}
	if err := send(SendParams{Agent: "dev-2", Text: strings.Repeat("a", MaxText+1)}); code(err) != CodeTooLarge {
		t.Errorf("text over the limit: %v", err)
	}
	maxSecs := int64(outbox.MaxExpiry / time.Second)
	for secs, want := range map[int64]string{4: CodeBadParams, 5: "", maxSecs: "", maxSecs + 1: CodeBadParams} {
		err := send(SendParams{Agent: "dev-2", Text: "x", ExpirySeconds: secs})
		if (want == "" && err != nil) || (want != "" && code(err) != want) {
			t.Errorf("expiry %d: %v", secs, err)
		}
	}
}

func TestAViewOfAFreshTaskHasNoContentAndTheContentLimitIsExact(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	if g := r.get(v, 0); g.Untrusted || g.Kind != "" || g.Content != "" {
		t.Errorf("a task with no message is shown with one: %+v", g)
	}
	for n, truncated := range map[int]bool{MaxContentView: false, MaxContentView + 1: true} {
		r.s.Update(pipeline.Update{Type: envelope.TypeStatus, TaskID: id16(v), Content: []byte(strings.Repeat("a", n))})
		g := r.get(v, 0)
		if g.Truncated != truncated || len(g.Content) != MaxContentView || !g.Untrusted {
			t.Errorf("%d bytes: truncated=%v len=%d", n, g.Truncated, len(g.Content))
		}
	}
}

func TestFinishedRecordsAreKeptForExactlyKeepDone(t *testing.T) {
	r := newRig(t)
	r.unlimited()
	v := r.send("dev-2", "x")
	r.s.Update(pipeline.Update{Type: envelope.TypeResult, TaskID: id16(v), Content: []byte("r")})
	r.clk.add(KeepDone)
	r.send("dev-2", "y") // makeRoom runs
	if _, err := r.s.Get(context.Background(), GetParams{TaskID: v.ID}); err != nil {
		t.Fatalf("dropped at exactly KeepDone: %v", err)
	}
	r.clk.add(time.Nanosecond)
	r.send("dev-2", "z")
	if _, err := r.s.Get(context.Background(), GetParams{TaskID: v.ID}); code(err) != CodeNotFound {
		t.Fatalf("kept past KeepDone: %v", err)
	}
}

func TestParseIDIsStrict(t *testing.T) {
	good := strings.Repeat("ab", 16)
	for s, want := range map[string]bool{
		good: true, good + "zz": false, good[:30]: false, good + "ab": false, strings.ToUpper(good): false, "": false, "zz" + good[2:]: false,
	} {
		if _, ok := parseID(s); ok != want {
			t.Errorf("%q: %v", s, ok)
		}
	}
}

func TestListCursorAndLimitBounds(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 3; i++ {
		r.send("dev-2", "x")
	}
	list := func(p ListParams) (ListResult, error) { return r.s.List(context.Background(), p) }
	// A cursor with a high byte set is read as a number, not bytewise.
	if res, err := list(ListParams{Cursor: "0000000000000100"}); err != nil || len(res.Tasks) != 3 {
		t.Errorf("high-byte cursor: %+v %v", res, err)
	}
	if res, err := list(ListParams{Cursor: "0000000000000002"}); err != nil || len(res.Tasks) != 1 {
		t.Errorf("low cursor: %+v %v", res, err)
	}
	if res, err := list(ListParams{Limit: 1}); err != nil || len(res.Tasks) != 1 || res.NextCursor == "" {
		t.Errorf("limit 1: %+v %v", res, err)
	}
	if res, err := list(ListParams{Limit: MaxLimit}); err != nil || len(res.Tasks) != 3 {
		t.Errorf("max limit: %+v %v", res, err)
	}
	for _, p := range []ListParams{{Limit: -1}, {Limit: MaxLimit + 1}, {Cursor: "00"}, {Cursor: "zz00000000000000"}, {State: "BOGUS"}} {
		if _, err := list(p); code(err) != CodeBadParams {
			t.Errorf("%+v: %v", p, err)
		}
	}
	if cursorOf(0x0102030405060708) != "0102030405060708" {
		t.Error("cursorOf")
	}
}

func TestCancelOfATaskTheOutboxHasAlreadyDeliveredSendsASignedCancel(t *testing.T) {
	r := newRig(t)
	v := r.send("dev-2", "x")
	r.n.abandon = outbox.ErrAlreadySent
	if _, err := r.s.Cancel(context.Background(), CancelParams{TaskID: v.ID}); err != nil || len(r.n.followed) != 1 || r.n.followed[0] != envelope.TypeCancel {
		t.Fatalf("%v %v", err, r.n.followed)
	}
	r.n.abandon = errors.New("SECRET")
	if _, err := r.s.Cancel(context.Background(), CancelParams{TaskID: v.ID}); code(err) != CodeInternal {
		t.Fatal(err)
	}
}

func TestAnExpiredUpdateEndsTheTaskAsFailedOrCanceled(t *testing.T) {
	r := newRig(t)
	a, b := r.send("dev-2", "x"), r.send("dev-2", "y")
	r.sent(a)
	r.s.Update(pipeline.Update{Expired: true, TaskID: id16(a)})
	if g := r.get(a, 0); g.State != Failed || g.Reason != ReasonExpired {
		t.Errorf("%+v", g)
	}
	r.sent(b)
	if _, err := r.s.Cancel(context.Background(), CancelParams{TaskID: b.ID}); err != nil {
		t.Fatal(err)
	}
	r.s.Update(pipeline.Update{Expired: true, TaskID: id16(b)})
	if g := r.get(b, 0); g.State != Canceled || g.Reason != ReasonExpired {
		t.Errorf("%+v", g)
	}
}

func TestEveryUpdateTypeMovesTheTaskToItsState(t *testing.T) {
	for typ, want := range map[envelope.Type]string{
		envelope.TypeStatus: Working, envelope.TypeInputRequired: InputRequired, envelope.TypeResult: Completed,
		envelope.TypeError: Failed, envelope.TypeCancel: Canceled,
	} {
		r := newRig(t)
		v := r.send("dev-2", "x")
		r.s.Update(pipeline.Update{Type: typ, TaskID: id16(v), Content: []byte("c")})
		if g := r.get(v, 0); g.State != want {
			t.Errorf("%v: %s, want %s", typ, g.State, want)
		}
	}
}

func TestQueryTextRules(t *testing.T) {
	for s, want := range map[string]bool{"": true, "a b": true, " ": true, "\x1f": false, "\x7f": false, "\t": false, "\xff": false, "é": true} {
		if validText(s) != want {
			t.Errorf("%q", s)
		}
	}
}

func TestFindAgentsLimitsAreExact(t *testing.T) {
	r := newRig(t)
	r.unlimited()
	find := func(q Query) error { _, err := r.s.FindAgents(context.Background(), q); return err }
	ok := []Query{{Text: strings.Repeat("a", maxQuery)}, {Tag: strings.Repeat("a", maxTag)}, {Limit: 0}, {Limit: MaxLimit}, {Cursor: strings.Repeat("ab", maxCursor/2)}}
	bad := []Query{{Text: strings.Repeat("a", maxQuery+1)}, {Tag: strings.Repeat("a", maxTag+1)}, {Limit: -1}, {Limit: MaxLimit + 1},
		{Cursor: strings.Repeat("ab", maxCursor/2+1)}, {Cursor: "abc"}, {Cursor: "zz"}, {Cursor: "AB"}, {Text: "\x00"}, {Tag: "\x00"}}
	for _, q := range ok {
		if err := find(q); err != nil {
			t.Errorf("%.20v: %v", q, err)
		}
	}
	for _, q := range bad {
		if err := find(q); code(err) != CodeBadParams {
			t.Errorf("%.20v: %v", q, err)
		}
	}
}

func TestABucketDoesNotRefillWhenTheClockGoesBackwards(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	b := newBucket(2, clk.now)
	if !b.take() || !b.take() || b.take() {
		t.Fatal("two tokens expected")
	}
	clk.add(-10 * time.Minute)
	if b.take() {
		t.Error("a clock set back refilled the bucket")
	}
	clk.add(30 * time.Second) // one token's worth since the (earlier) last reading
	if !b.take() {
		t.Error("no refill after time passed")
	}
}

func TestDirectoryReplyLimitsAreExact(t *testing.T) {
	g, d := newGW(t)
	pad := func(n int) string { // a reply of exactly n bytes
		base := `{"agents":[],"pad":""}`
		return `{"agents":[],"pad":"` + strings.Repeat("a", n-len(base)) + `"}`
	}
	g.body.Store(pad(maxDirReply))
	if _, err := d.Find(context.Background(), Query{}); err != nil {
		t.Errorf("a reply of exactly the limit: %v", err)
	}
	g.body.Store(pad(maxDirReply + 1))
	if _, err := d.Find(context.Background(), Query{}); err == nil {
		t.Error("a reply one byte over the limit")
	}
	agents := func(n int) string { return `{"agents":[` + strings.TrimSuffix(strings.Repeat(`{},`, n), ",") + `]}` }
	g.body.Store(agents(MaxLimit))
	if _, err := d.Find(context.Background(), Query{}); err != nil {
		t.Errorf("a full page: %v", err)
	}
	cur := func(n int) string { return `{"agents":[],"next_cursor":"` + strings.Repeat("ab", n/2) + `"}` }
	g.body.Store(cur(maxCursor))
	if _, err := d.Find(context.Background(), Query{}); err != nil {
		t.Errorf("a cursor of the limit: %v", err)
	}
	g.body.Store(cur(maxCursor + 2))
	if _, err := d.Find(context.Background(), Query{}); err == nil {
		t.Error("a cursor over the limit")
	}
	g.body.Store(`{"agents":[],"next_cursor":"abc"}`)
	if _, err := d.Find(context.Background(), Query{}); err == nil {
		t.Error("an odd-length cursor")
	}
}

func TestAFailedTokenFetchFailsEvenWithATokenReturned(t *testing.T) {
	_, d := newGW(t)
	d.Token = func(context.Context) (string, time.Time, error) {
		return "tok", time.Now().Add(time.Hour), errors.New("SECRET")
	}
	if _, err := d.Find(context.Background(), Query{}); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
}

func TestDirectoryUsesTheCallersHTTPClientWithoutFollowingRedirects(t *testing.T) {
	g, d := newGW(t)
	d.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"agents":[]}`)), Header: http.Header{}}, nil
	})}
	g.srv.Close()
	if p, err := d.Find(context.Background(), Query{}); err != nil || len(p.Agents) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
