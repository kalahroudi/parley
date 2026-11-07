// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adaptertest

import (
	"bufio"
	"encoding/json"
	"io"
	"sync"

	"github.com/kalahroudi/parley/internal/bot"
)

// acpChunk is the largest text sent in one message chunk.
const acpChunk = 32 << 10

// acpIn is a message the client sends.
type acpIn struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Prompt []struct {
			Text string `json:"text"`
		} `json:"prompt"`
		Meta struct {
			Parley InLine `json:"parley"`
		} `json:"_meta"`
	} `json:"params"`
}

// ServeACP runs b as an ACP agent over in and out, with the mapping the ACP adapter defines: a status is a plan update with
// one step in progress; a question is a message that ends the turn with _meta.parley.inputRequired, and the caller's answer
// is the next prompt of the session; an error of the bot (a plain one reaches the caller only as the fixed text of Start) is an error reply to the prompt that carries
// data.parley = "failure"; the result is the text of the message chunks of the last
// turn. A session/cancel, or the end of in, cancels the task. It returns when the task is over.
func ServeACP(b bot.Bot, in io.Reader, out io.Writer) {
	var wmu sync.Mutex
	send := func(v any) {
		line, _ := json.Marshal(v)
		wmu.Lock()
		defer wmu.Unlock()
		out.Write(append(line, '\n'))
	}
	reply := func(id json.RawMessage, result any) {
		send(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	}
	update := func(u map[string]any) {
		send(map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{"sessionId": "s1", "update": u}})
	}
	chunks := func(text []byte) {
		for len(text) > 0 {
			n := min(len(text), acpChunk)
			update(map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]string{"type": "text", "text": string(text[:n])}})
			text = text[n:]
		}
	}
	msgs := make(chan acpIn)
	go func() { // ends with in
		defer close(msgs)
		r := bufio.NewReaderSize(in, 1<<22)
		for {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return
			}
			var m acpIn
			if json.Unmarshal(line, &m) == nil {
				msgs <- m
			}
		}
	}()
	var c *Conv
	var outCh chan OutLine
	var prompt json.RawMessage // the prompt waiting for its reply
	for {
		select {
		case m, ok := <-msgs:
			if !ok {
				if c != nil {
					c.Cancel()
				}
				return
			}
			switch m.Method {
			case "initialize":
				reply(m.ID, map[string]any{"protocolVersion": 1, "agentCapabilities": map[string]any{}})
			case "session/new":
				reply(m.ID, map[string]string{"sessionId": "s1"})
			case "session/prompt":
				prompt = m.ID
				text := []byte(m.Params.Prompt[0].Text)
				if c == nil {
					first := m.Params.Meta.Parley
					first.Content = text
					c = Start(b, first)
					outCh = c.Out
				} else {
					c.Answers <- text
				}
			case "session/cancel":
				if c != nil {
					c.Cancel()
				}
				return
			}
		case o, ok := <-outCh:
			if !ok {
				return
			}
			switch o.Type {
			case "status":
				update(map[string]any{"sessionUpdate": "plan", "entries": []map[string]string{{"content": string(o.Content), "priority": "medium", "status": "in_progress"}}})
			case "question":
				chunks(o.Content)
				reply(prompt, map[string]any{"stopReason": "end_turn", "_meta": map[string]any{"parley": map[string]bool{"inputRequired": true}}})
			case "result":
				chunks(o.Content)
				reply(prompt, map[string]string{"stopReason": "end_turn"})
			default:
				send(map[string]any{"jsonrpc": "2.0", "id": prompt, "error": map[string]any{"code": -32000, "message": o.Message, "data": map[string]string{"parley": "failure"}}})
			}
		}
	}
}
