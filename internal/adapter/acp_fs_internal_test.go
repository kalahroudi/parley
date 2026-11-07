// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kalahroudi/parley/internal/bot"
)

// ownerSays is a gate that answers every request the same.
type ownerSays struct {
	ok    bool
	err   error
	asked int
}

func (o *ownerSays) Call(context.Context, bot.Task, string, []string, func()) (ToolReply, error) {
	o.asked++
	if o.ok {
		return ToolReply{Outcome: OutcomeOK}, o.err
	}
	return ToolReply{Outcome: "denied"}, o.err
}

func (*ownerSays) End([16]byte) {}

func convIn(dir string, g Tools) *acpConv {
	return &acpConv{dir: dir, gate: g, sid: "s"}
}

func TestRelativeAcceptsOnlyPathsInsideTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	c := convIn(dir, nil)
	pad := func(n int) string { return strings.Repeat("a", n-len(dir)-1) }
	for name, tc := range map[string]struct {
		path string
		want string
		ok   bool
	}{
		"a file":                  {filepath.Join(dir, "a"), "a", true},
		"nested":                  {filepath.Join(dir, "a", "b"), filepath.Join("a", "b"), true},
		"dots inside":             {filepath.Join(dir, "a", "..", "b"), "b", true},
		"a name starting with ..": {filepath.Join(dir, "..a"), "..a", true},
		"the longest path":        {dir + "/" + pad(maxACPPath), pad(maxACPPath), true},
		"one byte too long":       {dir + "/" + pad(maxACPPath+1), "", false},
		"the directory":           {dir, "", false},
		"the directory, dotted":   {dir + "/.", "", false},
		"its parent":              {filepath.Dir(dir), "", false},
		"above it":                {filepath.Join(dir, "..", "x"), "", false},
		"a sibling":               {dir + "x/a", "", false},
		"relative":                {"a", "", false},
		"empty":                   {"", "", false},
		"newline":                 {filepath.Join(dir, "a\nb"), "", false},
		"bidi":                    {filepath.Join(dir, "a‮b"), "", false},
		"invalid UTF-8":           {filepath.Join(dir, "a\xffb"), "", false},
		"a space":                 {filepath.Join(dir, "a b"), "a b", true},
	} {
		got, ok := c.relative(tc.path)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: %q %v", name, got, ok)
		}
	}
}

func TestReadFileLimitsAndErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("max", strings.Repeat("a", MaxACPFile))
	write("over", strings.Repeat("a", MaxACPFile+1))
	if s, e := readFile(dir, "max", nil, nil); e != nil || len(s) != MaxACPFile {
		t.Fatalf("a file of the largest size: %v", e)
	}
	if _, e := readFile(dir, "over", nil, nil); e != errTooBig {
		t.Fatalf("%v", e)
	}
	if _, e := readFile(filepath.Join(dir, "none"), "x", nil, nil); e != errFile {
		t.Fatalf("a directory that does not exist: %v", e)
	}
	defer SetFileIO(func(io.Reader) ([]byte, error) { return nil, errors.New("read") }, replaceContent)()
	if _, e := readFile(dir, "max", nil, nil); e != errFile {
		t.Fatalf("a read that fails: %v", e)
	}
}

func TestWriteFileErrors(t *testing.T) {
	dir := t.TempDir()
	if e := writeFile(filepath.Join(dir, "none"), "x", "y"); e != errFile {
		t.Fatalf("a directory that does not exist: %v", e)
	}
	if e := writeFile(dir, "f", "ok"); e != nil {
		t.Fatalf("%v", e)
	}
	f, err := os.Open(filepath.Join(dir, "f"))
	if err != nil {
		t.Fatal(err)
	}
	if replaceContent(f, "x") == nil { // opened read-only
		t.Fatal("a file that cannot be written was written")
	}
	f.Close()
	if replaceContent(f, "x") == nil {
		t.Fatal("a closed file was written")
	}
	defer SetFileIO(io.ReadAll, func(*os.File, string) error { return errors.New("write") })()
	if e := writeFile(dir, "g", "y"); e != errFile {
		t.Fatalf("a write that fails: %v", e)
	}
}

// The edges of a file operation: the largest content is accepted and one byte more is not asked about, a failing gate ends the
// task, a request without a gate is not served, and a denial does nothing.
func TestFSEdges(t *testing.T) {
	dir := t.TempDir()
	run := func(g Tools, params string, write bool) (any, *rpcError, error) {
		return convIn(dir, g).fs(context.Background(), []byte(params), write)
	}
	big := func(n int) string {
		path, _ := json.Marshal(filepath.Join(dir, "w"))
		return `{"sessionId":"s","path":` + string(path) + `,"content":"` + strings.Repeat("a", n) + `"}`
	}
	g := &ownerSays{ok: true}
	if _, e, err := run(g, big(MaxACPFile), true); e != nil || err != nil || g.asked != 1 {
		t.Fatalf("the largest content: %v %v", e, err)
	}
	if _, e, err := run(g, big(MaxACPFile+1), true); e != errInvalid || err != nil || g.asked != 1 {
		t.Fatalf("one byte too much: %v %v (asked %d)", e, err, g.asked)
	}
	gerr := &ownerSays{err: errors.New("gone")}
	if _, _, err := run(gerr, big(1), true); err == nil {
		t.Fatal("a failing gate did not end the task")
	}
	if _, e, err := run(nil, big(1), true); e != errNoMethod || err != nil {
		t.Fatalf("no gate: %v %v", e, err)
	}
	deny := &ownerSays{}
	if _, e, err := run(deny, big(1), true); e != errDenied || err != nil || deny.asked != 1 {
		t.Fatalf("denied: %v %v", e, err)
	}
}

type recorder struct {
	statuses []string
	err      error
}

func (r *recorder) Status(_ context.Context, b []byte) error {
	r.statuses = append(r.statuses, string(b))
	return r.err
}

func (*recorder) Ask(context.Context, []byte) ([]byte, error) { return nil, nil }

// Statuses: a repeat and an empty text are dropped, exactly MaxStatuses are sent, text is cut at MaxACPStatus bytes (not in
// the middle of a character) and made plain, and a failing session ends the task.
func TestStatusLimits(t *testing.T) {
	r := &recorder{}
	c := &acpConv{s: r}
	for i := 0; i < MaxStatuses+5; i++ {
		if err := c.status(context.Background(), "step "+strings.Repeat("x", i%7)+string(rune('a'+i%26))+strings.Repeat("y", i/26)); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.statuses) != MaxStatuses || c.ignored != 5 {
		t.Fatalf("%d statuses, %d ignored", len(r.statuses), c.ignored)
	}
	r = &recorder{}
	c = &acpConv{s: r}
	for _, s := range []string{strings.Repeat("a", MaxACPStatus), strings.Repeat("a", MaxACPStatus+1) + "b", "é" + strings.Repeat("a", MaxACPStatus-2) + "é"} {
		if err := c.status(context.Background(), s); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.statuses[0]) != MaxACPStatus || r.statuses[1] != strings.Repeat("a", MaxACPStatus) || r.statuses[2] != "é"+strings.Repeat("a", MaxACPStatus-2) {
		t.Fatalf("%q", r.statuses)
	}
	boom := errors.New("boom")
	c = &acpConv{s: &recorder{err: boom}}
	if err := c.status(context.Background(), "x"); err != boom {
		t.Fatalf("%v", err)
	}
	c = &acpConv{s: &recorder{}}
	for _, empty := range []string{"", ""} {
		if err := c.status(context.Background(), empty); err != nil {
			t.Fatal(err)
		}
	}
	if c.ignored != 2 || c.statuses != 0 {
		t.Fatalf("empty statuses: %d ignored, %d sent", c.ignored, c.statuses)
	}
}

func TestPlainTextCutsOnCharactersAndHidesWhatIsNotPrintable(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 3, "abc"}, {"abc", 2, "ab"}, {"", 5, ""}, {"éé", 3, "é"}, {"éé", 4, "éé"}, {"a b", 3, "a b"},
		{"a\x00b", 9, "a?b"}, {"a‮b", 9, "a?b"}, {"a\xffb", 9, "a\uFFFDb"}, {"\t", 9, "?"},
	} {
		if got := plainText(tc.in, tc.n); got != tc.want {
			t.Errorf("plainText(%q, %d) = %q", tc.in, tc.n, got)
		}
	}
}

// Only a prompt's error can be the agent's declared failure (the prompts have ids from 3), and only with the marker.
func TestResponseAcceptsAFailureOnlyFromAPrompt(t *testing.T) {
	c := &acpConv{}
	marked := rpcMessage{ID: []byte("2"), Error: []byte(`{"code":1,"message":"m","data":{"parley":"failure"}}`)}
	if _, err := c.response(2, marked); err != errACPRemote {
		t.Fatalf("session/new: %v", err)
	}
	marked.ID = []byte("3")
	var f *bot.Failure
	if _, err := c.response(3, marked); !errors.As(err, &f) || f.Message != "m" {
		t.Fatalf("a prompt: %v", err)
	}
	marked.ID = []byte("4")
	if _, err := c.response(4, marked); !errors.As(err, &f) {
		t.Fatalf("a later prompt: %v", err)
	}
	if _, err := c.response(3, rpcMessage{ID: []byte("4"), Result: []byte("{}")}); err != errProtocol {
		t.Fatalf("another id: %v", err)
	}
}

// The permission count covers asked and unasked requests alike, and stops at the limit.
func TestRequestsToTheOwnerAreCounted(t *testing.T) {
	g := &ownerSays{ok: true}
	c := &acpConv{gate: g, s: &recorder{}}
	for i := 0; i < MaxACPPermissions; i++ {
		if ok, err := c.ask(context.Background(), ToolACPPermission); !ok || err != nil {
			t.Fatalf("request %d: %v %v", i, ok, err)
		}
	}
	if _, err := c.ask(context.Background(), ToolACPPermission); err != errProtocol || g.asked != MaxACPPermissions {
		t.Fatalf("one too many: %v (asked %d)", err, g.asked)
	}
	c = &acpConv{s: &recorder{}}
	if ok, err := c.ask(context.Background(), ToolACPPermission); ok || err != nil {
		t.Fatalf("no gate: %v %v", ok, err)
	}
	// a gate's yes with an error is no
	c = &acpConv{gate: &ownerSays{ok: true, err: errors.New("x")}, s: &recorder{}}
	if ok, err := c.ask(context.Background(), ToolACPRead); ok || err == nil {
		t.Fatalf("%v %v", ok, err)
	}
}
