// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
			case typeStatus, typeQuestion, typeResult, typeError:
			default:
				t.Fatalf("type %q admitted", m.Type)
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
	if _, err := converse(context.Background(), p, s); err != errProtocol {
		t.Fatalf("%v", err)
	}
	if s.asked != MaxQuestions || len(p.answered) != MaxQuestions || p.answered[0] != 1 || p.answered[MaxQuestions-1] != MaxQuestions {
		t.Fatalf("asked %d, answered %v", s.asked, p.answered)
	}
	p, s = &scripted{say: repeat(typeQuestion, MaxQuestions)}, &counting{}
	if _, err := converse(context.Background(), p, s); err != io.EOF || s.asked != MaxQuestions {
		t.Fatalf("exactly the limit is allowed: %v, asked %d", err, s.asked)
	}
	p, s = &scripted{say: repeat(typeStatus, MaxStatuses+5)}, &counting{}
	if _, err := converse(context.Background(), p, s); err != errProtocol || s.statuses != MaxStatuses {
		t.Fatalf("%v, %d statuses", err, s.statuses)
	}
	p, s = &scripted{say: repeat(typeStatus, MaxStatuses)}, &counting{}
	if _, err := converse(context.Background(), p, s); err != io.EOF || s.statuses != MaxStatuses {
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
