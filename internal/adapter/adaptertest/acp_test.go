// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adaptertest_test

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/adapter/adaptertest"
	"github.com/kalahroudi/parley/internal/bot/bottest"
)

// acpClient talks to ServeACP over pipes.
type acpClient struct {
	t    *testing.T
	in   io.WriteCloser
	out  *bufio.Reader
	done chan struct{}
}

func newACPClient(t *testing.T) *acpClient {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &acpClient{t: t, in: inW, out: bufio.NewReaderSize(outR, 1<<22), done: make(chan struct{})}
	go func() {
		adaptertest.ServeACP(&bottest.Fake{}, inR, outW)
		outW.Close()
		close(c.done)
	}()
	t.Cleanup(func() { inW.Close() })
	return c
}

func (c *acpClient) send(line string) {
	c.t.Helper()
	if _, err := io.WriteString(c.in, line+"\n"); err != nil {
		c.t.Fatal(err)
	}
}

func (c *acpClient) read() map[string]json.RawMessage {
	c.t.Helper()
	line, err := c.out.ReadBytes('\n')
	if err != nil {
		c.t.Fatalf("the agent ended: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(line, &m); err != nil {
		c.t.Fatalf("%s: %v", line, err)
	}
	return m
}

func (c *acpClient) ended() {
	c.t.Helper()
	select {
	case <-c.done:
	case <-time.After(10 * time.Second):
		c.t.Fatal("the agent did not end")
	}
}

func prompt(id int, text string) string {
	q, _ := json.Marshal(text)
	return `{"jsonrpc":"2.0","id":` + string(rune('0'+id)) + `,"method":"session/prompt","params":{"sessionId":"s1","prompt":[{"type":"text","text":` + string(q) + `}],"_meta":{"parley":{"id":"0100000000000000000000000000000a","caller":"d"}}}}`
}

func (c *acpClient) handshake() {
	c.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1}}`)
	if r := c.read(); string(r["id"]) != "1" || !strings.Contains(string(r["result"]), `"protocolVersion":1`) {
		c.t.Fatalf("%s", r["result"])
	}
	c.send(`{"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":"/","mcpServers":[]}}`)
	if r := c.read(); string(r["id"]) != "2" || !strings.Contains(string(r["result"]), `"sessionId":"s1"`) {
		c.t.Fatalf("%s", r["result"])
	}
}

func chunkText(t *testing.T, m map[string]json.RawMessage) string {
	t.Helper()
	var p struct {
		Update struct {
			Kind    string `json:"sessionUpdate"`
			Content struct{ Text string }
		}
	}
	if err := json.Unmarshal(m["params"], &p); err != nil || p.Update.Kind != "agent_message_chunk" {
		t.Fatalf("%s %v", m["params"], err)
	}
	return p.Update.Content.Text
}

func TestServeACPResultAndStatusAndQuestion(t *testing.T) {
	c := newACPClient(t)
	c.handshake()
	c.send(prompt(3, "echo hi"))
	if got := chunkText(t, c.read()); got != "echo hi" {
		t.Fatalf("%q", got)
	}
	if r := c.read(); string(r["id"]) != "3" || string(r["result"]) != `{"stopReason":"end_turn"}` {
		t.Fatalf("%s", r["result"])
	}
	c.ended()

	c = newACPClient(t)
	c.handshake()
	c.send(prompt(3, "status working"))
	if m := c.read(); string(m["method"]) != `"session/update"` || !strings.Contains(string(m["params"]), `"sessionUpdate":"plan"`) || !strings.Contains(string(m["params"]), `"content":"working"`) || !strings.Contains(string(m["params"]), `"status":"in_progress"`) {
		t.Fatalf("%s", m["params"])
	}
	if got := chunkText(t, c.read()); got != "done" {
		t.Fatalf("%q", got)
	}
	c.read()
	c.ended()

	c = newACPClient(t)
	c.handshake()
	c.send(prompt(3, "ask which?"))
	if got := chunkText(t, c.read()); got != "which?" {
		t.Fatalf("%q", got)
	}
	if r := c.read(); !strings.Contains(string(r["result"]), `"inputRequired":true`) {
		t.Fatalf("%s", r["result"])
	}
	c.send(prompt(4, "blue"))
	if got := chunkText(t, c.read()); got != "answer: blue" {
		t.Fatalf("%q", got)
	}
	if r := c.read(); string(r["id"]) != "4" || string(r["result"]) != `{"stopReason":"end_turn"}` {
		t.Fatalf("%s", r["result"])
	}
	c.ended()
}

func TestServeACPFailureAndLargeResult(t *testing.T) {
	c := newACPClient(t)
	c.handshake()
	c.send(prompt(3, "fail no such file"))
	if r := c.read(); string(r["id"]) != "3" || !strings.Contains(string(r["error"]), `"message":"no such file"`) || !strings.Contains(string(r["error"]), `"parley":"failure"`) {
		t.Fatalf("%s", r["error"])
	}
	c.ended()

	c = newACPClient(t)
	c.handshake()
	c.send(prompt(3, "big"))
	total := 0
	for {
		m := c.read()
		if m["result"] != nil {
			break
		}
		total += len(chunkText(t, m))
	}
	if total <= 32<<10 {
		t.Fatalf("%d bytes: not sent in several chunks", total)
	}
	c.ended()
}

// session/cancel, and the end of the input, cancel a task that is running; a line that is not JSON is skipped.
func TestServeACPCancelAndEndOfInput(t *testing.T) {
	c := newACPClient(t)
	c.send("not json")
	c.handshake()
	c.send(prompt(3, "block"))
	c.send(`{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s1"}}`)
	c.ended()

	c = newACPClient(t)
	c.handshake()
	c.send(prompt(3, "block"))
	c.in.Close()
	c.ended()

	c = newACPClient(t)
	c.in.Close()
	c.ended()

	c = newACPClient(t)
	c.send(`{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s1"}}`)
	c.ended()
}
