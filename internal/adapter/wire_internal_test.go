// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// FuzzReadMessage: whatever a bot writes, reading it never panics, never yields
// a message outside the protocol and never holds more than MaxLine bytes of a line.
func FuzzReadMessage(f *testing.F) {
	for _, s := range []string{
		`{"type":"result","content":"b2s="}`,
		`{"type":"status","content":""}`,
		`{"type":"question","content":"cT8="}`,
		`{"type":"error","message":"no such file"}`,
		`{"type":"result","content":"@@@"}`,
		`{"type":"tool","tool":"grep","args":["a","b"]}`, `{"type":"tool"}`, `{"type":"tool","content":"YQ=="}`, `{"type":"status","tool":"x"}`,
		`{"type":"shout"}`, `[]`, `null`, "", `{"type":"result"} trailing`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		r := bufio.NewReaderSize(strings.NewReader(line+"\n"+line), 16)
		for {
			m, err := readMessage(r)
			if err != nil {
				return
			}
			switch m.Type {
			case typeStatus, typeQuestion, typeResult, typeError, typeTool:
			default:
				t.Fatalf("type %q admitted", m.Type)
			}
			if len(m.Args) > MaxToolArgs || (m.Type != typeTool && (m.Tool != "" || m.Args != nil)) {
				t.Fatal("tool fields outside a tool request")
			}
			if len(m.Content) > MaxLine || len(m.Message) > MaxLine {
				t.Fatal("a message beyond the line limit")
			}
		}
	})
}

func TestReadMessageRefusesALineOverTheLimitWithoutReadingItAll(t *testing.T) {
	src := &countingReader{r: strings.NewReader(`{"type":"result","content":"` + strings.Repeat("A", 4*MaxLine) + `"}` + "\n")}
	if _, err := readMessage(bufio.NewReader(src)); err != errTooLong {
		t.Fatal(err)
	}
	if src.n > MaxLine+64<<10 {
		t.Fatalf("read %d bytes of a line that is refused at %d", src.n, MaxLine)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) { n, err := c.r.Read(p); c.n += n; return n, err }

// A line of exactly MaxLine is accepted: one result of MaxContent+1 bytes fits,
// so Host (not the adapter) says "too large".
func TestAMaximalResultFitsOneLine(t *testing.T) {
	big := bytes.Repeat([]byte("x"), pipeline.MaxContent+1)
	line := encode(toBot{}, big, true)
	var m message
	if err := json.Unmarshal(bytes.TrimSuffix(line, []byte("\n")), &m); err != nil || !bytes.Equal(m.Content, big) {
		t.Fatalf("round trip: %v", err)
	}
	line = bytes.Replace(line, []byte(`"v":0,"type":"","id":""`), []byte(`"type":"result"`), 1)
	if len(line)-1 > MaxLine {
		t.Fatalf("a maximal result line is %d bytes, over MaxLine %d", len(line)-1, MaxLine)
	}
	if _, err := readMessage(bufio.NewReaderSize(bytes.NewReader(line), 4096)); err != nil {
		t.Fatal(err)
	}
}

func TestEncodedLinesScrub(t *testing.T) {
	l := taskLine(bot.Task{Content: []byte("SECRET-CANARY")})
	if !bytes.Contains(l, []byte("U0VDUkVULUNBTkFSWQ==")) || l[len(l)-1] != '\n' {
		t.Fatalf("%s", l)
	}
	if string(cancelLine([16]byte{1})) != `{"v":1,"type":"cancel","id":"01000000000000000000000000000000"}`+"\n" {
		t.Fatalf("%s", cancelLine([16]byte{1}))
	}
	if !strings.Contains(string(answerLine([16]byte{}, 3, []byte("a"))), `"turn":3`) {
		t.Fatal("answer turn")
	}
}

func TestReadMessageIsStrict(t *testing.T) {
	for name, line := range map[string]string{
		"unknown field":    `{"type":"result","content":"b2s=","tool":"rm"}`,
		"second value":     `{"type":"result"} {"type":"result"}`,
		"trailing text":    `{"type":"result"} x`,
		"wrong field type": `{"type":"error","message":5}`,
	} {
		if _, err := readMessage(bufio.NewReader(strings.NewReader(line + "\n"))); err != errProtocol {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// scripted is a peer that says what a test lists, then ends the stream, with no network and no clock.
type scripted struct {
	say      []message
	answered []int
}

func (p *scripted) next() (message, error) {
	if len(p.say) == 0 {
		return message{}, io.EOF
	}
	m := p.say[0]
	p.say = p.say[1:]
	return m, nil
}

func (p *scripted) answer(_ context.Context, turn int, _ []byte) error {
	p.answered = append(p.answered, turn)
	return nil
}

type counting struct{ statuses, asked int }

func (c *counting) Status(context.Context, []byte) error { c.statuses++; return nil }
func (c *counting) Ask(context.Context, []byte) ([]byte, error) {
	c.asked++
	return []byte("a"), nil
}

// A bot that asks forever is served exactly MaxQuestions times, numbered from 1, and then fails: not one more, not one
// fewer. Likewise for status messages.
func TestConverseBoundsQuestionsAndStatuses(t *testing.T) {
	repeat := func(typ string, n int) []message {
		out := make([]message, n)
		for i := range out {
			out[i] = message{Type: typ}
		}
		return out
	}
	p, s := &scripted{say: repeat(typeQuestion, MaxQuestions+5)}, &counting{}
	if _, err := converse(context.Background(), p, s, nil); err != errProtocol {
		t.Fatalf("%v", err)
	}
	if s.asked != MaxQuestions || len(p.answered) != MaxQuestions || p.answered[0] != 1 || p.answered[MaxQuestions-1] != MaxQuestions {
		t.Fatalf("asked %d, answered %v", s.asked, p.answered)
	}
	p, s = &scripted{say: repeat(typeQuestion, MaxQuestions)}, &counting{}
	if _, err := converse(context.Background(), p, s, nil); err != io.EOF || s.asked != MaxQuestions {
		t.Fatalf("exactly the limit is allowed: %v, asked %d", err, s.asked)
	}
	p, s = &scripted{say: repeat(typeStatus, MaxStatuses+5)}, &counting{}
	if _, err := converse(context.Background(), p, s, nil); err != errProtocol || s.statuses != MaxStatuses {
		t.Fatalf("%v, %d statuses", err, s.statuses)
	}
	p, s = &scripted{say: repeat(typeStatus, MaxStatuses)}, &counting{}
	if _, err := converse(context.Background(), p, s, nil); err != io.EOF || s.statuses != MaxStatuses {
		t.Fatalf("exactly the limit is allowed: %v, %d statuses", err, s.statuses)
	}
}

// The capacity of an encoded line is exactly its length, so the content is copied once, into a buffer that can be
// cleared (a growing buffer would leave copies behind).
func TestEncodeAllocatesExactly(t *testing.T) {
	for _, l := range [][]byte{taskLine(bot.Task{ID: [16]byte{1}, Context: "c", Content: []byte("some content")}), answerLine([16]byte{2}, 3, []byte("a")), cancelLine([16]byte{3})} {
		if cap(l) != len(l) {
			t.Fatalf("cap %d, len %d: %q", cap(l), len(l), l)
		}
	}
}

// The limit is on the whole line, however many reads it takes: MaxLine bytes pass, one more does not.
func TestReadMessageLimitIsExact(t *testing.T) {
	line := func(n int) string {
		const head, tail = `{"type":"result","content":"`, `"}`
		k := (n - len(head) - len(tail)) / 4 * 4 // valid base64, then spaces up to the exact length
		return head + strings.Repeat("A", k) + tail + strings.Repeat(" ", n-len(head)-k-len(tail))
	}
	for _, size := range []int{16, 4096} { // lines that span many reads, and fewer
		if m, err := readMessage(bufio.NewReaderSize(strings.NewReader(line(MaxLine)+"\n"), size)); err != nil || m.Type != typeResult {
			t.Fatalf("size %d: a line of MaxLine bytes: %v", size, err)
		}
		if _, err := readMessage(bufio.NewReaderSize(strings.NewReader(line(MaxLine+1)+"\n"), size)); err != errTooLong {
			t.Fatalf("size %d: a line of MaxLine+1 bytes: %v", size, err)
		}
	}
}

func TestReadMessageAdmitsToolRequestsOnly(t *testing.T) {
	read := func(line string) (message, error) {
		return readMessage(bufio.NewReader(strings.NewReader(line + "\n")))
	}
	m, err := read(`{"type":"tool","tool":"grep","args":["a","b c"]}`)
	if err != nil || m.Type != typeTool || m.Tool != "grep" || len(m.Args) != 2 || m.Args[1] != "b c" {
		t.Fatalf("%+v %v", m, err)
	}
	if m, err = read(`{"type":"tool"}`); err != nil || m.Tool != "" {
		t.Fatalf("a bare request is the broker's to refuse: %+v %v", m, err)
	}
	many := `{"type":"tool","tool":"t","args":[` + strings.Repeat(`"",`, MaxToolArgs-1) + `""]}`
	if _, err = read(many); err != nil {
		t.Fatalf("MaxToolArgs arguments: %v", err)
	}
	for name, line := range map[string]string{
		"too many args":      `{"type":"tool","tool":"t","args":[` + strings.Repeat(`"",`, MaxToolArgs) + `""]}`,
		"content":            `{"type":"tool","tool":"t","content":"YQ=="}`,
		"message":            `{"type":"tool","tool":"t","message":"m"}`,
		"args not strings":   `{"type":"tool","tool":"t","args":[1]}`,
		"tool in a result":   `{"type":"result","tool":"t"}`,
		"args in a status":   `{"type":"status","args":[]}`,
		"tool in a question": `{"type":"question","tool":"t"}`,
		"tool in an error":   `{"type":"error","tool":"t"}`,
		"a tool result":      `{"type":"tool_result"}`,
		"unknown field":      `{"type":"tool","tool":"t","x":1}`,
	} {
		if _, err := read(line); err != errProtocol {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// fakeTools answers tool requests and records what it was asked.
type fakeTools struct {
	calls  []string
	given  [][]byte // the content slices handed out
	waits  int
	ended  [][16]byte
	reply  ToolReply
	err    error
	onWait bool
}

func (f *fakeTools) Call(_ context.Context, t bot.Task, tool string, args []string, onWait func()) (ToolReply, error) {
	f.calls = append(f.calls, tool+"|"+strings.Join(args, ","))
	if f.onWait {
		onWait()
	}
	r := f.reply
	r.Content = append([]byte(nil), r.Content...)
	f.given = append(f.given, r.Content)
	return r, f.err
}
func (f *fakeTools) End(id [16]byte) { f.ended = append(f.ended, id) }

func TestConverseServesToolRequests(t *testing.T) {
	ft := &fakeTools{reply: ToolReply{Outcome: "ok", Exit: 0, Content: []byte("framed")}, onWait: true}
	var sent [][]byte
	tc := &toolConv{tools: ft, task: bot.Task{ID: [16]byte{5}}, send: func(_ context.Context, l []byte) error { sent = append(sent, l); return nil }}
	say := []message{{Type: typeTool, Tool: "grep", Args: []string{"a"}}, {Type: typeTool, Tool: "ls"}, {Type: typeResult, Content: []byte("done")}}
	s := &counting{}
	out, err := converse(context.Background(), &scripted{say: say}, s, tc)
	if err != nil || string(out) != "done" || fmt.Sprint(ft.calls) != "[grep|a ls|]" || s.statuses != 2 || len(sent) != 2 {
		t.Fatalf("%q %v %v %d %d", out, err, ft.calls, s.statuses, len(sent))
	}
	for _, c := range ft.given {
		if !bytes.Equal(c, make([]byte, len(c))) {
			t.Fatalf("the tool output was kept: %q", c)
		}
	}
	var l struct {
		V, Turn   int
		Type, ID  string
		Outcome   string
		Untrusted bool
		Content   []byte
	}
	if err := json.Unmarshal(sent[1], &l); err != nil || l.Type != "tool_result" || l.Turn != 2 || l.ID != "05000000000000000000000000000000" ||
		l.Outcome != "ok" || !l.Untrusted || string(l.Content) != "framed" || l.V != 1 {
		t.Fatalf("%+v %v %s", l, err, sent[1])
	}
}

func TestConverseToolRequestsAreBoundedAndNeedTools(t *testing.T) {
	req := func(n int) []message {
		out := make([]message, n)
		for i := range out {
			out[i] = message{Type: typeTool, Tool: "t"}
		}
		return out
	}
	if _, err := converse(context.Background(), &scripted{say: req(1)}, &counting{}, nil); err != errProtocol {
		t.Fatalf("a bot without tools asked for one: %v", err)
	}
	ft := &fakeTools{}
	tc := &toolConv{tools: ft, send: func(context.Context, []byte) error { return nil }}
	if _, err := converse(context.Background(), &scripted{say: req(MaxToolRequests + 5)}, &counting{}, tc); err != errProtocol || len(ft.calls) != MaxToolRequests {
		t.Fatalf("%v after %d", err, len(ft.calls))
	}
	ft = &fakeTools{}
	tc.tools = ft
	if _, err := converse(context.Background(), &scripted{say: req(MaxToolRequests)}, &counting{}, tc); err != io.EOF || len(ft.calls) != MaxToolRequests {
		t.Fatalf("exactly the limit is served: %v after %d", err, len(ft.calls))
	}
}

func TestConverseToolFailuresEndTheTask(t *testing.T) {
	boom := errors.New("boom")
	tc := &toolConv{tools: &fakeTools{err: boom}, send: func(context.Context, []byte) error { return nil }}
	if _, err := converse(context.Background(), &scripted{say: []message{{Type: typeTool, Tool: "t"}}}, &counting{}, tc); err != boom {
		t.Fatalf("call: %v", err)
	}
	tc = &toolConv{tools: &fakeTools{}, send: func(context.Context, []byte) error { return boom }}
	if _, err := converse(context.Background(), &scripted{say: []message{{Type: typeTool, Tool: "t"}}}, &counting{}, tc); err != boom {
		t.Fatalf("send: %v", err)
	}
}
