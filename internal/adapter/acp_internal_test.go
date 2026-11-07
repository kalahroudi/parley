// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// FuzzParseRPC: whatever an agent writes, parsing it never panics and never yields a message outside JSON-RPC 2.0: a
// response has an id and exactly one of result and error, a request or notification has a method and neither, and an id
// that is echoed back is a short number or string.
func FuzzParseRPC(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hi"}}}}`,
		`{"jsonrpc":"2.0","id":"p-1","method":"session/request_permission","params":{"options":[{"optionId":"no","kind":"reject_once"}]}}`,
		`{"jsonrpc":"2.0","id":null,"method":"x"}`, `{"jsonrpc":"1.0","id":1,"result":{}}`, `{"jsonrpc":"2.0","id":1}`,
		`{"jsonrpc":"2.0","id":1,"result":1,"error":{}}`, `{"jsonrpc":"2.0","id":{},"method":"x"}`, `[]`, `null`, "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		m, err := parseRPC([]byte(line))
		if err != nil {
			return
		}
		if m.JSONRPC != "2.0" {
			t.Fatal("version admitted")
		}
		if m.isResponse() {
			if m.ID == nil || m.Params != nil || (m.Result == nil) == (m.Error == nil) {
				t.Fatal("malformed response admitted")
			}
			return
		}
		if m.Result != nil || m.Error != nil {
			t.Fatal("request with a result admitted")
		}
		if m.ID != nil && !echoableID(m.ID) {
			t.Fatal("id that cannot be echoed admitted")
		}
	})
}

func TestParseRPCRefusesWhatIsNotJSONRPC(t *testing.T) {
	for name, line := range map[string]string{
		"not json":                `nonsense`,
		"wrong version":           `{"jsonrpc":"1.0","id":1,"result":{}}`,
		"no version":              `{"id":1,"result":{}}`,
		"unknown field":           `{"jsonrpc":"2.0","id":1,"result":{},"x":1}`,
		"duplicate key":           `{"jsonrpc":"2.0","id":1,"result":{},"id":2}`,
		"duplicate result":        `{"jsonrpc":"2.0","id":1,"result":{"a":1},"result":{}}`,
		"miscased key":            `{"jsonrpc":"2.0","id":1,"Result":{}}`,
		"miscased duplicate":      `{"jsonrpc":"2.0","id":1,"result":{},"RESULT":{}}`,
		"two values":              `{"jsonrpc":"2.0","id":1,"result":{}} {"jsonrpc":"2.0","id":2,"result":{}}`,
		"trailing text":           `{"jsonrpc":"2.0","id":1,"result":{}} x`,
		"response without id":     `{"jsonrpc":"2.0","result":{}}`,
		"response with neither":   `{"jsonrpc":"2.0","id":1}`,
		"response with both":      `{"jsonrpc":"2.0","id":1,"result":{},"error":{}}`,
		"response with params":    `{"jsonrpc":"2.0","id":1,"result":{},"params":{}}`,
		"request with result":     `{"jsonrpc":"2.0","id":1,"method":"m","result":{}}`,
		"notification with error": `{"jsonrpc":"2.0","method":"m","error":{}}`,
		"null id":                 `{"jsonrpc":"2.0","id":null,"method":"m"}`,
		"object id":               `{"jsonrpc":"2.0","id":{},"method":"m"}`,
		"bool id":                 `{"jsonrpc":"2.0","id":true,"method":"m"}`,
		"long id":                 `{"jsonrpc":"2.0","id":"` + strings.Repeat("a", maxACPID) + `","method":"m"}`,
	} {
		if _, err := parseRPC([]byte(line)); err != errProtocol {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, line := range map[string]string{
		"result":       `{"jsonrpc":"2.0","id":1,"result":null}`,
		"error":        `{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"m"}}`,
		"notification": `{"jsonrpc":"2.0","method":"m","params":{"future":1}}`,
		"number id":    `{"jsonrpc":"2.0","id":-7,"method":"m"}`,
		"string id":    `{"jsonrpc":"2.0","id":"` + strings.Repeat("a", maxACPID-2) + `","method":"m"}`,
	} {
		if _, err := parseRPC([]byte(line)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The escaping is checked against encoding/json for every byte that may appear in valid UTF-8 text, and the length it
// promises is the length it appends (the buffer is sized with it so that the one copy we hold can be scrubbed).
func TestAppendJSONTextMatchesEncodingJSON(t *testing.T) {
	var all []byte
	for r := rune(0); r < 0x3000; r++ {
		if r == 0x2028 || r == 0x2029 {
			continue // encoding/json escapes these for HTML safety; both forms decode to the same text
		}
		all = utf8.AppendRune(all, r)
	}
	all = append(all, "😀 \"\\\x7f\x00\x1f"...)
	for _, in := range [][]byte{nil, []byte("plain"), []byte("a\"b\\c\n\r\t\x00\x1f"), all} {
		got := appendJSONText(nil, in)
		if len(got) != jsonTextLen(in) {
			t.Fatalf("length %d, promised %d", len(got), jsonTextLen(in))
		}
		var back string
		if err := json.Unmarshal([]byte(`"`+string(got)+`"`), &back); err != nil || back != string(in) {
			t.Fatalf("round trip: %v", err)
		}
		if strings.ContainsAny(string(got), "\n\r") {
			t.Fatal("a raw line break inside the string: the message would be split")
		}
	}
}

func TestPromptLineIsOneLineWithTheTaskAsDataFields(t *testing.T) {
	tk := bot.Task{ID: [16]byte{0xab}, Context: "c\"1", Caller: "dev\nx", Owner: "o@example.com", Content: []byte("hi \"there\"\n\x01é"),
		Expiry: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}
	line := promptLine(3, "s\"1", tk.Content, taskMeta(tk))
	if line[len(line)-1] != '\n' || strings.Count(string(line), "\n") != 1 {
		t.Fatalf("%q", line)
	}
	if cap(line) != len(line) {
		t.Fatalf("the buffer is not sized exactly (%d of %d): a reallocation would leave a copy that cannot be scrubbed", len(line), cap(line))
	}
	var m struct {
		ID     int    `json:"id"`
		Method string `json:"method"`
		Params struct {
			Session string `json:"sessionId"`
			Prompt  []struct {
				Type, Text string
			} `json:"prompt"`
			Meta struct {
				Parley map[string]string `json:"parley"`
			} `json:"_meta"`
		} `json:"params"`
	}
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatal(err)
	}
	p := m.Params
	if m.ID != 3 || m.Method != "session/prompt" || p.Session != "s\"1" || len(p.Prompt) != 1 || p.Prompt[0].Type != "text" || p.Prompt[0].Text != string(tk.Content) {
		t.Fatalf("%+v", m)
	}
	want := map[string]string{"task": "ab000000000000000000000000000000", "context": "c\"1", "caller": "dev\nx", "owner": "o@example.com", "expires": "2030-01-02T03:04:05Z"}
	for k, v := range want {
		if p.Meta.Parley[k] != v {
			t.Errorf("%s = %q", k, p.Meta.Parley[k])
		}
	}
	if len(p.Meta.Parley) != len(want) {
		t.Errorf("%v", p.Meta.Parley)
	}
}

func TestDenialPicksTheRejectOptionTheAgentOffered(t *testing.T) {
	long := strings.Repeat("x", maxACPSession+1)
	for name, tc := range map[string]struct{ params, want string }{
		"reject once":        {`{"options":[{"optionId":"y","kind":"allow_once"},{"optionId":"n","kind":"reject_once"}]}`, "n"},
		"once before always": {`{"options":[{"optionId":"na","kind":"reject_always"},{"optionId":"n","kind":"reject_once"}]}`, "n"},
		"reject always":      {`{"options":[{"optionId":"y","kind":"allow_always"},{"optionId":"na","kind":"reject_always"}]}`, "na"},
		"only allow":         {`{"options":[{"optionId":"y","kind":"allow_once"},{"optionId":"ya","kind":"allow_always"}]}`, ""},
		"no options":         {`{}`, ""},
		"not an object":      {`[1]`, ""},
		"no params":          {``, ""},
		"empty id":           {`{"options":[{"optionId":"","kind":"reject_once"}]}`, ""},
		"id too long":        {`{"options":[{"optionId":"` + long + `","kind":"reject_once"}]}`, ""},
		"unknown kind":       {`{"options":[{"optionId":"n","kind":"reject_forever"}]}`, ""},
	} {
		got, _ := json.Marshal(denial(json.RawMessage(tc.params)))
		want := `{"outcome":{"outcome":"cancelled"}}`
		if tc.want != "" {
			want = `{"outcome":{"optionId":"` + tc.want + `","outcome":"selected"}}`
		}
		if string(got) != want {
			t.Errorf("%s: %s", name, got)
		}
	}
}

// An empty message chunk adds no text, so it counts against the ignored messages: a flood of them ends the task.
func TestEmptyChunksAreCounted(t *testing.T) {
	c := &acpConv{sid: "s"}
	empty := json.RawMessage(`{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":""}}}`)
	for i := 0; i < MaxACPIgnored; i++ {
		if err := c.update(context.Background(), empty); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
	}
	if err := c.update(context.Background(), empty); err != errProtocol {
		t.Fatalf("one past the limit: %v", err)
	}
}

// The limits are exact: a request id of the longest length and one that starts with the lowest and the highest digit
// can be echoed, a reject option with the longest id can be chosen, and a reply of exactly a result's size is not cut.
func TestACPLimitsAreExact(t *testing.T) {
	for _, id := range []string{`0`, `9`, `-1`, `"` + strings.Repeat("a", maxACPID-2) + `"`} {
		if !echoableID(json.RawMessage(id)) {
			t.Errorf("id %s", id)
		}
	}
	for _, id := range []string{`/`, `:`, `true`, `null`, `{}`, `[1]`} {
		if echoableID(json.RawMessage(id)) {
			t.Errorf("id %s", id)
		}
	}
	id := strings.Repeat("x", maxACPSession)
	got, _ := json.Marshal(denial(json.RawMessage(`{"options":[{"optionId":"` + id + `","kind":"reject_once"}]}`)))
	if want := `{"outcome":{"optionId":"` + id + `","outcome":"selected"}}`; string(got) != want {
		t.Errorf("longest option id refused")
	}
	c := &acpConv{sid: "s"}
	text := func(n int) json.RawMessage {
		return json.RawMessage(`{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"` + strings.Repeat("a", n) + `"}}}`)
	}
	if err := c.update(context.Background(), text(pipeline.MaxContent)); err != nil || len(c.text) != pipeline.MaxContent {
		t.Fatalf("a result's size: %v", err)
	}
	if err := c.update(context.Background(), text(1)); err != errACPFull || len(c.text) != pipeline.MaxContent+1 {
		t.Fatalf("one byte more: %v %d", err, len(c.text))
	}
}
