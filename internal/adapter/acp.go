// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// ErrACPConfig means the ACP adapter's command, directory or environment is not acceptable.
var ErrACPConfig = errors.New("adapter: invalid ACP configuration")

// Limits on what an ACP agent may say.
const (
	// MaxACPIgnored bounds the messages of one task that carry nothing the adapter uses (thoughts, plans, tool progress,
	// requests it refuses); more is a protocol error.
	MaxACPIgnored = 4096
	// MaxACPPermissions bounds the permission requests of one task. Every one is denied.
	MaxACPPermissions = 64

	maxACPSession = 256 // the longest session id or option id accepted
	maxACPID      = 64  // the longest request id of the agent that is echoed back
)

// TextACPNotText is what the caller sees when the task is not text: an ACP prompt is text.
const TextACPNotText = "this bot takes text only"

var (
	errACPRemote = errors.New("adapter: the ACP agent reported an error")
	errACPFull   = errors.New("adapter: the ACP agent's reply is larger than any result") // internal: the reply is cut
)

// ACPConfig configures the ACP adapter. The fields mean what they do for CLIConfig, except that Dir is required: it is
// the session's working directory, which the protocol wants as an absolute path.
type ACPConfig struct {
	Command string
	Args    []string
	Dir     string
	Env     []string
}

// ACP is a bot that speaks the Agent Client Protocol (JSON-RPC 2.0 over standard input and output, one message per
// line): the program is run once per task, as for the CLI adapter, with the same containment. The task is one prompt of
// one new session; the agent's message text is the result. Nothing is granted to the agent: the client advertises no file
// system and no terminal capability, answers a request for one with "method not found", and denies every permission
// request. An agent that must act on the machine by itself is a tool-using skill and needs the owner's approval (skill).
// ACP has no message for a question to the caller and none for a status text the adapter could pass on without passing on
// the agent's thoughts, so neither is used.
type ACP struct{ cfg CLIConfig }

// NewACP validates cfg and returns the adapter.
func NewACP(cfg ACPConfig) (*ACP, error) {
	c, err := NewCLI(CLIConfig{Command: cfg.Command, Args: cfg.Args, Dir: cfg.Dir, Env: cfg.Env})
	if err != nil || cfg.Dir == "" {
		return nil, ErrACPConfig
	}
	return &ACP{cfg: c.cfg}, nil
}

// Handle implements bot.Bot.
func (a *ACP) Handle(ctx context.Context, t bot.Task, _ bot.Session) ([]byte, error) {
	if !utf8.Valid(t.Content) {
		return nil, &bot.Failure{Message: TextACPNotText}
	}
	p, stop, err := startBot(ctx, a.cfg, t.ID)
	if err != nil {
		return nil, err
	}
	defer stop()
	return (&acpConv{p: p}).run(ctx, a.cfg.Dir, t)
}

// acpInitialize offers no capability: the agent gets no file system and no terminal from us.
var acpInitialize = []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{"fs":{"readTextFile":false,"writeTextFile":false},"terminal":false},"clientInfo":{"name":"parley","title":"Parley","version":"1"}}}
`)

// acpConv is one task's conversation with an agent.
type acpConv struct {
	p           *cliPeer
	sid         string
	text        []byte // the agent's message so far, at most one byte more than a result may hold
	ignored     int
	permissions int
}

// run is the whole conversation: initialize, one new session, one prompt.
func (c *acpConv) run(ctx context.Context, dir string, t bot.Task) ([]byte, error) {
	res, err := c.call(ctx, 1, acpInitialize)
	if err != nil {
		return nil, err
	}
	var init struct {
		Version int `json:"protocolVersion"`
	}
	if json.Unmarshal(res, &init) != nil || init.Version != 1 {
		return nil, errors.New("adapter: the ACP agent does not speak protocol version 1")
	}
	res, err = c.call(ctx, 2, request(2, "session/new", struct {
		Cwd string   `json:"cwd"`
		MCP []string `json:"mcpServers"` // none: the agent gets no servers from us
	}{dir, []string{}}))
	if err != nil {
		return nil, err
	}
	var ns struct {
		SessionID string `json:"sessionId"`
	}
	if json.Unmarshal(res, &ns) != nil || ns.SessionID == "" || len(ns.SessionID) > maxACPSession {
		return nil, errProtocol
	}
	c.sid = ns.SessionID
	line := promptLine(c.sid, t)
	c.p.scrub = append(c.p.scrub, line)
	res, err = c.call(ctx, 3, line)
	if errors.Is(err, errACPFull) {
		return c.text, nil
	}
	if err != nil {
		return nil, err
	}
	var pr struct {
		StopReason string `json:"stopReason"`
	}
	if json.Unmarshal(res, &pr) != nil || pr.StopReason != "end_turn" {
		return nil, errors.New("adapter: the ACP agent did not finish the task")
	}
	return c.text, nil
}

// rpcMessage is one line from the agent.
type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

func (m *rpcMessage) isResponse() bool { return m.Method == "" }
func (m *rpcMessage) isRequest() bool  { return m.Method != "" && m.ID != nil }

// parseRPC reads one JSON-RPC 2.0 message strictly: the envelope has no unknown, duplicate or miscased key and no trailing data, a response has
// an id and exactly one of result and error, a request or notification has a method and neither, and a request's id is
// a short number or string (it is echoed back). What is inside params and result is read leniently by the caller, because
// ACP lets either side add fields.
func parseRPC(line []byte) (rpcMessage, error) {
	var m rpcMessage
	// ExactKeys refuses a duplicate key and a key that differs from a field only in case (encoding/json would fold it into
	// the field and keep the last value).
	if !localsock.ExactKeys(line, "jsonrpc", "id", "method", "params", "result", "error") {
		return rpcMessage{}, errProtocol
	}
	if json.Unmarshal(line, &m) != nil || m.JSONRPC != "2.0" {
		return rpcMessage{}, errProtocol
	}
	if m.isResponse() {
		if m.ID == nil || m.Params != nil || (m.Result == nil) == (m.Error == nil) {
			return rpcMessage{}, errProtocol
		}
		return m, nil
	}
	if m.Result != nil || m.Error != nil || (m.ID != nil && !echoableID(m.ID)) {
		return rpcMessage{}, errProtocol
	}
	return m, nil
}

func echoableID(id json.RawMessage) bool {
	b := id[0]
	return len(id) <= maxACPID && (b == '"' || b == '-' || (b >= '0' && b <= '9'))
}

// call writes line, a request with the given id, and handles what the agent sends until the reply to it comes.
func (c *acpConv) call(ctx context.Context, id int, line []byte) (json.RawMessage, error) {
	if err := c.p.write(ctx, line); err != nil {
		return nil, err
	}
	for {
		raw, err := readLine(c.p.r)
		if err == nil {
			var m rpcMessage
			if m, err = parseRPC(raw); err == nil {
				if m.isResponse() {
					if string(m.ID) != strconv.Itoa(id) {
						return nil, errProtocol
					}
					if m.Error != nil {
						return nil, errACPRemote
					}
					return m.Result, nil
				}
				if m.isRequest() {
					err = c.serve(ctx, m)
				} else {
					err = c.notify(m)
				}
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
	}
}

// notify handles a notification: the text of a message chunk of our session is kept, everything else is counted and dropped.
func (c *acpConv) notify(m rpcMessage) error {
	if m.Method == "session/update" && c.sid != "" {
		return c.update(m.Params)
	}
	return c.ignore()
}

func (c *acpConv) ignore() error {
	if c.ignored++; c.ignored > MaxACPIgnored {
		return errProtocol
	}
	return nil
}

// update takes the text of a message chunk and ignores every other kind of update. It fails with errACPFull as soon as the
// text is larger than a result may be: Host turns that into its "too large" answer, and the agent is killed with the task.
func (c *acpConv) update(params json.RawMessage) error {
	var u struct {
		SessionID string `json:"sessionId"`
		Update    struct {
			Kind    string          `json:"sessionUpdate"`
			Content json.RawMessage `json:"content"`
		} `json:"update"`
	}
	if json.Unmarshal(params, &u) != nil || u.SessionID != c.sid {
		return errProtocol
	}
	if u.Update.Kind != "agent_message_chunk" {
		return c.ignore()
	}
	var chunk struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(u.Update.Content, &chunk) != nil {
		return errProtocol
	}
	if chunk.Type != "text" || chunk.Text == "" {
		return c.ignore() // an image or a link is not part of a text result; an empty chunk adds nothing, so it is counted
	}
	c.text = append(c.text, chunk.Text...)
	if len(c.text) > pipeline.MaxContent {
		c.text = c.text[:pipeline.MaxContent+1]
		return errACPFull
	}
	return nil
}

// serve answers a request of the agent. A permission request is denied (the reject option the agent offered, or
// "cancelled" if it offered none); any other request, a file or terminal operation included, is "method not found".
func (c *acpConv) serve(ctx context.Context, m rpcMessage) error {
	reply := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  any             `json:"result,omitempty"`
		Error   any             `json:"error,omitempty"`
	}{JSONRPC: "2.0", ID: m.ID}
	if m.Method == "session/request_permission" {
		if c.permissions++; c.permissions > MaxACPPermissions {
			return errProtocol
		}
		reply.Result = denial(m.Params)
	} else {
		if err := c.ignore(); err != nil {
			return err
		}
		reply.Error = map[string]any{"code": -32601, "message": "method not found"}
	}
	line, _ := json.Marshal(reply) // strings, numbers and a raw value that was valid JSON cannot fail
	return c.p.write(ctx, append(line, '\n'))
}

func denial(params json.RawMessage) map[string]any {
	var p struct {
		Options []struct {
			ID   string `json:"optionId"`
			Kind string `json:"kind"`
		} `json:"options"`
	}
	_ = json.Unmarshal(params, &p) // on a failure there are no options: the request is cancelled
	for _, kind := range []string{"reject_once", "reject_always"} {
		for _, o := range p.Options {
			if o.Kind == kind && o.ID != "" && len(o.ID) <= maxACPSession {
				return map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": o.ID}}
			}
		}
	}
	return map[string]any{"outcome": map[string]any{"outcome": "cancelled"}}
}

func request(id int, method string, params any) []byte {
	line, _ := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}{"2.0", id, method, params}) // strings and plain structs cannot fail
	return append(line, '\n')
}

// promptLine is the prompt request: the task content is the one text block, and what the task says about itself (ids and
// names) travels in the request's _meta, as JSON fields, so that it is never mixed into text the agent reads as its own
// instructions. The content is escaped into a buffer of exactly the right size, so that the one copy we hold can be scrubbed.
func promptLine(sid string, t bot.Task) []byte {
	meta, _ := json.Marshal(struct {
		Task    string `json:"task"`
		Context string `json:"context,omitempty"`
		Caller  string `json:"caller,omitempty"`
		Owner   string `json:"owner,omitempty"`
		Expires string `json:"expires,omitempty"`
	}{hex.EncodeToString(t.ID[:]), t.Context, t.Caller, t.Owner, t.Expiry.UTC().Format(time.RFC3339)})
	sidJSON, _ := json.Marshal(sid)
	const head = `{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":`
	const mid = `,"prompt":[{"type":"text","text":"`
	const tail = `"}],"_meta":{"parley":`
	out := make([]byte, 0, len(head)+len(sidJSON)+len(mid)+jsonTextLen(t.Content)+len(tail)+len(meta)+4)
	out = append(out, head...)
	out = append(out, sidJSON...)
	out = append(out, mid...)
	out = appendJSONText(out, t.Content)
	out = append(out, tail...)
	out = append(out, meta...)
	return append(out, '}', '}', '}', '\n')
}

// appendJSONText appends s, which must be valid UTF-8, as the inside of a JSON string.
func appendJSONText(dst, s []byte) []byte {
	const hexDigits = "0123456789abcdef"
	for _, b := range s {
		if b == '"' || b == '\\' {
			dst = append(dst, '\\', b)
			continue
		}
		if b < 0x20 {
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[b>>4], hexDigits[b&15])
			continue
		}
		dst = append(dst, b)
	}
	return dst
}

// jsonTextLen is the length appendJSONText appends.
func jsonTextLen(s []byte) int {
	n := len(s)
	for _, b := range s {
		if b == '"' || b == '\\' {
			n++
		} else if b < 0x20 {
			n += 5
		}
	}
	return n
}
