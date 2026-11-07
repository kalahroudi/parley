// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// ErrACPConfig means the ACP adapter's command, directory or environment is not acceptable.
var ErrACPConfig = errors.New("adapter: invalid ACP configuration")

// Limits on what an ACP agent may say.
const (
	// MaxACPIgnored bounds the messages of one task that carry nothing the adapter uses (thoughts, tool progress, empty
	// chunks, plans past the status limit, requests it refuses); more is a protocol error.
	MaxACPIgnored = 4096
	// MaxACPPermissions bounds the requests of one task that the owner is asked about (permissions and file operations,
	// refused ones included).
	MaxACPPermissions = 64
	// MaxACPFile bounds a file the agent reads or writes through us.
	MaxACPFile = 1048576
	// MaxACPStatus bounds a status text taken from a plan.
	MaxACPStatus = 1024

	maxACPSession = 256 // the longest session id or option id accepted
	maxACPID      = 64  // the longest request id of the agent that is echoed back
	maxACPPath    = 1024
	maxACPTitle   = 256
	maxACPKind    = 32
)

// cancelGrace is how long an agent has to end itself after session/cancel before it is killed.
const cancelGrace = time.Duration(250e6)

// What the owner is asked about, as the names of the tools of the approval broker (internal/toolgate) and the one outcome
// that means yes.
const (
	ToolACPPermission = "acp_permission" // arguments: the kind and the title of the agent's tool call
	ToolACPRead       = "acp_read"       // arguments: the path
	ToolACPWrite      = "acp_write"      // arguments: the path, the size and the SHA-256 of the content
	OutcomeOK         = "ok"             // the Outcome of an approved call (toolgate.OutcomeOK)
)

// Texts the caller sees.
const (
	TextACPNotText = "this bot takes text only"
	TextACPRefused = "the agent refused the task"
)

// What the agent is told when a request of its is not carried out. Fixed: never an OS error or a path.
var (
	errDenied     = &rpcError{-32000, "denied"}
	errInvalid    = &rpcError{-32602, "invalid params"}
	errNotText    = &rpcError{-32000, "not a text file"}
	errTooBig     = &rpcError{-32000, "file too large"}
	errFile       = &rpcError{-32000, "file operation failed"}
	errNoMethod   = &rpcError{-32601, "method not found"}
	errACPRemote  = errors.New("adapter: the ACP agent reported an error")
	errACPFull    = errors.New("adapter: the ACP agent's reply is larger than any result") // internal: the reply is cut
	errACPVersion = errors.New("adapter: the ACP agent does not speak protocol version 1")
)

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ACPConfig configures the ACP adapter. The fields mean what they do for CLIConfig, except that Dir is required: it is
// the session's working directory, which the protocol wants as an absolute path, and the only place a file operation
// reaches.
type ACPConfig struct {
	Command string
	Args    []string
	Dir     string
	Env     []string
	// Gate puts the requests of the agent to the owner: the tool names are ToolACPPermission, ToolACPRead and ToolACPWrite,
	// and only OutcomeOK allows. Without a Gate every permission request is denied and no file operation is offered.
	Gate Tools
}

// ACP is a bot that speaks the Agent Client Protocol (JSON-RPC 2.0 over standard input and output, one message per
// line): the program is run once per task, as for the CLI adapter, with the same containment. See the package comment for
// what is mapped to what, and what the agent can and cannot do.
type ACP struct {
	cfg  CLIConfig
	gate Tools
}

// NewACP validates cfg and returns the adapter.
func NewACP(cfg ACPConfig) (*ACP, error) {
	c, err := NewCLI(CLIConfig{Command: cfg.Command, Args: cfg.Args, Dir: cfg.Dir, Env: cfg.Env})
	if err != nil || cfg.Dir == "" {
		return nil, ErrACPConfig
	}
	return &ACP{cfg: c.cfg, gate: cfg.Gate}, nil
}

// Handle implements bot.Bot.
func (a *ACP) Handle(ctx context.Context, t bot.Task, s bot.Session) ([]byte, error) {
	if !utf8.Valid(t.Content) {
		return nil, &bot.Failure{Message: TextACPNotText}
	}
	c := &acpConv{task: t, s: s, gate: a.gate, dir: a.cfg.Dir}
	if a.gate != nil {
		defer a.gate.End(t.ID)
	}
	p, stop, err := startBot(ctx, a.cfg, t.ID, c.cancel)
	if err != nil {
		return nil, err
	}
	defer stop()
	c.p = p
	res, err := c.run(ctx)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return res, err
}

// The first request: it offers the file system only when there is a gate to ask the owner, and never a terminal.
var (
	acpInitialize   = initialize(false)
	acpInitializeFS = initialize(true)
)

func initialize(fs bool) []byte {
	return request(1, "initialize", map[string]any{
		"protocolVersion": 1,
		"clientCapabilities": map[string]any{
			"fs":       map[string]bool{"readTextFile": fs, "writeTextFile": fs},
			"terminal": false,
		},
		"clientInfo": map[string]string{"name": "parley", "title": "Parley", "version": "1"},
	})
}

// acpConv is one task's conversation with an agent.
type acpConv struct {
	task bot.Task
	s    bot.Session
	gate Tools
	dir  string
	p    *cliPeer

	mu  sync.Mutex // orders what we write, and guards sid for cancel
	sid string

	text     []byte // the agent's message so far in this turn, at most one byte more than a result may hold
	last     string // the last status sent
	statuses int
	ignored  int
	gated    int
}

// write sends one line to the agent.
func (c *acpConv) write(ctx context.Context, line []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.p.write(ctx, line)
}

func (c *acpConv) session() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sid
}

// cancel is what happens when the task's context ends: the agent is told with session/cancel and has cancelGrace to end
// itself, then it is killed with everything it started. A write that does not go through (an agent that does not read)
// is ended by that kill.
func (c *acpConv) cancel(p *cliPeer) {
	kill := time.AfterFunc(cancelGrace, p.terminate)
	_ = kill // never stopped: the task's end kills as well, and a kill after the reap is a no-op
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sid != "" {
		_, _ = p.in.Write(notification("session/cancel", struct {
			SessionID string `json:"sessionId"`
		}{c.sid}))
	}
}

// run is the whole conversation: initialize, one new session, a prompt, and a further prompt for each question.
func (c *acpConv) run(ctx context.Context) ([]byte, error) {
	first := acpInitialize
	if c.gate != nil {
		first = acpInitializeFS
	}
	res, err := c.call(ctx, 1, first)
	if err != nil {
		return nil, err
	}
	var ini struct {
		Version int `json:"protocolVersion"`
	}
	if json.Unmarshal(res, &ini) != nil || ini.Version != 1 {
		return nil, errACPVersion
	}
	res, err = c.call(ctx, 2, request(2, "session/new", struct {
		Cwd string   `json:"cwd"`
		MCP []string `json:"mcpServers"` // none: the agent gets no servers from us
	}{c.dir, []string{}}))
	if err != nil {
		return nil, err
	}
	var ns struct {
		SessionID string `json:"sessionId"`
	}
	if json.Unmarshal(res, &ns) != nil || ns.SessionID == "" || len(ns.SessionID) > maxACPSession {
		return nil, errProtocol
	}
	c.mu.Lock()
	c.sid = ns.SessionID
	c.mu.Unlock()
	content, meta := c.task.Content, taskMeta(c.task)
	for id, questions := 3, 0; ; id++ {
		line := promptLine(id, ns.SessionID, content, meta)
		if id > 3 {
			clear(content) // the answer: the one copy we hold is in the line, which is scrubbed at the end
		}
		c.p.scrub = append(c.p.scrub, line)
		c.text = c.text[:0]
		res, err = c.call(ctx, id, line)
		if errors.Is(err, errACPFull) {
			return c.text, nil
		}
		if err != nil {
			return nil, err
		}
		var pr struct {
			StopReason string `json:"stopReason"`
			Meta       struct {
				Parley struct {
					InputRequired bool `json:"inputRequired"`
				} `json:"parley"`
			} `json:"_meta"`
		}
		if json.Unmarshal(res, &pr) != nil {
			return nil, errProtocol
		}
		if pr.StopReason == "refusal" {
			return nil, &bot.Failure{Message: TextACPRefused}
		}
		if pr.StopReason != "end_turn" {
			return nil, errors.New("adapter: the ACP agent did not finish the task")
		}
		if !pr.Meta.Parley.InputRequired {
			return c.text, nil
		}
		if questions++; questions > MaxQuestions {
			return nil, errProtocol
		}
		answer, err := c.s.Ask(ctx, c.text)
		clear(c.text)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(answer) {
			clear(answer)
			return nil, &bot.Failure{Message: TextACPNotText}
		}
		content, meta = answer, answerMeta(c.task)
	}
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

// parseRPC reads one JSON-RPC 2.0 message strictly: the envelope has no unknown, duplicate or miscased key and no trailing
// data, a response has an id and exactly one of result and error, a request or notification has a method and neither, and
// a request's id is a short number or string (it is echoed back). What is inside params and result is read leniently by the
// caller, because ACP lets either side add fields.
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
	if err := c.write(ctx, line); err != nil {
		return nil, err
	}
	for {
		raw, err := readLine(c.p.r)
		if err == nil {
			var m rpcMessage
			if m, err = parseRPC(raw); err == nil {
				if m.isResponse() {
					return c.response(id, m)
				}
				if m.isRequest() {
					err = c.serve(ctx, m)
				} else {
					err = c.notify(ctx, m)
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

// response checks the reply to request id. An error of the prompt that carries the marker of a declared failure is the
// agent's own word for the caller; every other error is an error of the task whose text goes nowhere.
func (c *acpConv) response(id int, m rpcMessage) (json.RawMessage, error) {
	if string(m.ID) != strconv.Itoa(id) {
		return nil, errProtocol
	}
	if m.Error == nil {
		return m.Result, nil
	}
	var e struct {
		Message string `json:"message"`
		Data    struct {
			Parley string `json:"parley"`
		} `json:"data"`
	}
	if id >= 3 && json.Unmarshal(m.Error, &e) == nil && e.Data.Parley == ACPFailureMarker {
		return nil, &bot.Failure{Message: e.Message}
	}
	return nil, errACPRemote
}

// ACPFailureMarker is the value of error.data.parley in the error reply to a prompt that makes the error's message a
// failure declared for the caller (the equivalent of an "error" line of the CLI protocol).
const ACPFailureMarker = "failure"

func (c *acpConv) ignore() error {
	if c.ignored++; c.ignored > MaxACPIgnored {
		return errProtocol
	}
	return nil
}

// notify handles a notification: the text of a message chunk and the step of a plan, for our session, are used; everything
// else is counted and dropped.
func (c *acpConv) notify(ctx context.Context, m rpcMessage) error {
	if m.Method == "session/update" && c.session() != "" {
		return c.update(ctx, m.Params)
	}
	return c.ignore()
}

// update takes the text of a message chunk and the step in progress of a plan, and ignores every other kind of update. It
// fails with errACPFull as soon as the text is larger than a result may be: Host turns that into its "too large" answer,
// and the agent is killed with the task.
func (c *acpConv) update(ctx context.Context, params json.RawMessage) error {
	var u struct {
		SessionID string `json:"sessionId"`
		Update    struct {
			Kind    string          `json:"sessionUpdate"`
			Content json.RawMessage `json:"content"`
			Entries []struct {
				Content string `json:"content"`
				Status  string `json:"status"`
			} `json:"entries"`
		} `json:"update"`
	}
	if json.Unmarshal(params, &u) != nil || u.SessionID != c.session() {
		return errProtocol
	}
	if u.Update.Kind == "plan" {
		for _, e := range u.Update.Entries {
			if e.Status == "in_progress" {
				return c.status(ctx, e.Content)
			}
		}
		return c.ignore()
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

// status sends the step in progress to the caller, once for a text that repeats and not at all past MaxStatuses.
func (c *acpConv) status(ctx context.Context, text string) error {
	if text == "" || text == c.last || c.statuses >= MaxStatuses {
		return c.ignore()
	}
	c.statuses++
	c.last = text
	return c.s.Status(ctx, []byte(plainText(text, MaxACPStatus)))
}

// serve answers a request of the agent: a permission request or a file operation is put to the owner through the gate and
// done only if the owner allows it; any other request, a terminal operation included, is "method not found".
func (c *acpConv) serve(ctx context.Context, m rpcMessage) error {
	var res any = json.RawMessage("null")
	var rerr *rpcError
	var err error
	switch m.Method {
	case "session/request_permission":
		res, err = c.permission(ctx, m.Params)
	case "fs/read_text_file":
		res, rerr, err = c.fs(ctx, m.Params, false)
	case "fs/write_text_file":
		res, rerr, err = c.fs(ctx, m.Params, true)
	default:
		rerr, err = errNoMethod, c.ignore()
	}
	if err != nil {
		return err
	}
	reply := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  any             `json:"result,omitempty"`
		Error   *rpcError       `json:"error,omitempty"`
	}{JSONRPC: "2.0", ID: m.ID, Error: rerr}
	if rerr == nil {
		reply.Result = res
	}
	line, _ := json.Marshal(reply) // strings, numbers and a raw value that was valid JSON cannot fail
	line = append(line, '\n')
	c.p.scrub = append(c.p.scrub, line)
	return c.write(ctx, line)
}

// ask puts one request to the owner and reports whether it was allowed. The error is the end of the task.
func (c *acpConv) ask(ctx context.Context, tool string, args ...string) (bool, error) {
	if err := c.count(); err != nil {
		return false, err
	}
	if c.gate == nil {
		return false, nil
	}
	r, err := c.gate.Call(ctx, c.task, tool, args, func() { _ = c.s.Status(ctx, []byte(TextToolWaiting)) })
	clear(r.Content)
	return err == nil && r.Outcome == OutcomeOK, err
}

// permission answers a permission request: the owner is asked, and only an allow_once option the agent offered is chosen,
// when the owner says yes. Otherwise the agent is told no, with the reject option it offered or "cancelled".
func (c *acpConv) permission(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		ToolCall struct {
			Title string `json:"title"`
			Kind  string `json:"kind"`
		} `json:"toolCall"`
		Options []struct {
			ID   string `json:"optionId"`
			Kind string `json:"kind"`
		} `json:"options"`
	}
	_ = json.Unmarshal(params, &p) // on a failure there are no options: the request is cancelled
	allow := optionID(p.Options, "allow_once")
	ok := false
	if allow != "" {
		var err error
		if ok, err = c.ask(ctx, ToolACPPermission, plainText(p.ToolCall.Kind, maxACPKind), plainText(p.ToolCall.Title, maxACPTitle)); err != nil {
			return nil, err
		}
	} else if err := c.count(); err != nil {
		return nil, err
	}
	if ok {
		return selected(allow), nil
	}
	return denial(params), nil
}

// count counts a request that was not put to the owner against the limit.
func (c *acpConv) count() error {
	if c.gated++; c.gated > MaxACPPermissions {
		return errProtocol
	}
	return nil
}

// optionID is the id of the first option of the kind, if it is a usable id.
func optionID(opts []struct {
	ID   string `json:"optionId"`
	Kind string `json:"kind"`
}, kind string) string {
	for _, o := range opts {
		if o.Kind == kind && o.ID != "" && len(o.ID) <= maxACPSession {
			return o.ID
		}
	}
	return ""
}

func selected(id string) map[string]any {
	return map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": id}}
}

// denial is the answer "no": the reject option the agent offered, or "cancelled" if it offered none.
func denial(params json.RawMessage) map[string]any {
	var p struct {
		Options []struct {
			ID   string `json:"optionId"`
			Kind string `json:"kind"`
		} `json:"options"`
	}
	_ = json.Unmarshal(params, &p) // on a failure there are no options: the request is cancelled
	for _, kind := range []string{"reject_once", "reject_always"} {
		if id := optionID(p.Options, kind); id != "" {
			return selected(id)
		}
	}
	return map[string]any{"outcome": map[string]any{"outcome": "cancelled"}}
}

// plainText makes s something the owner can read as it is: at most n bytes of printable characters, the others replaced
// by "?" (a control, bidirectional or invalid character is not shown to the owner as what it is).
func plainText(s string, n int) string {
	out := make([]rune, 0, len(s))
	size := 0
	for _, r := range s {
		if r != ' ' && !unicode.IsPrint(r) {
			r = '?'
		}
		if size += utf8.RuneLen(r); size > n {
			break
		}
		out = append(out, r)
	}
	return string(out)
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

func notification(method string, params any) []byte {
	line, _ := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}{"2.0", method, params}) // likewise
	return append(line, '\n')
}

// taskMeta is what the task says about itself: ids and names travel in the prompt request's _meta, as JSON fields, so that
// they are never mixed into text the agent reads as its own instructions.
func taskMeta(t bot.Task) []byte {
	meta, _ := json.Marshal(struct {
		Task    string `json:"task"`
		Context string `json:"context,omitempty"`
		Caller  string `json:"caller,omitempty"`
		Owner   string `json:"owner,omitempty"`
		Expires string `json:"expires,omitempty"`
	}{hex.EncodeToString(t.ID[:]), t.Context, t.Caller, t.Owner, t.Expiry.UTC().Format(time.RFC3339)})
	return meta
}

// answerMeta marks a prompt as the caller's answer to the agent's question.
func answerMeta(t bot.Task) []byte {
	meta, _ := json.Marshal(struct {
		Task   string `json:"task"`
		Answer bool   `json:"answer"`
	}{hex.EncodeToString(t.ID[:]), true})
	return meta
}

// promptLine is the prompt request with the given id: the content is the one text block. The content is escaped into a
// buffer of exactly the right size, so that the one copy we hold can be scrubbed.
func promptLine(id int, sid string, content, meta []byte) []byte {
	sidJSON, _ := json.Marshal(sid)
	head := `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"session/prompt","params":{"sessionId":`
	const mid = `,"prompt":[{"type":"text","text":"`
	const tail = `"}],"_meta":{"parley":`
	out := make([]byte, 0, len(head)+len(sidJSON)+len(mid)+jsonTextLen(content)+len(tail)+len(meta)+4)
	out = append(out, head...)
	out = append(out, sidJSON...)
	out = append(out, mid...)
	out = appendJSONText(out, content)
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
