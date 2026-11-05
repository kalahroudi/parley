// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"bufio"
	"bytes"
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
