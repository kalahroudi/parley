// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// Limits on what a bot may send.
const (
	// MaxLine fits one result of MaxContent+1 bytes (so Host can answer "too
	// large" itself) in base64 with room for the object around it.
	MaxLine      = (pipeline.MaxContent+1+2)/3*4 + 4096
	MaxStatuses  = 1024
	MaxQuestions = 16
	// MaxToolRequests bounds the tool requests of one task, refused ones included; MaxToolArgs the arguments of one
	// (a request with more is a protocol error, well above any manifest's limit).
	MaxToolRequests = 64
	MaxToolArgs     = 64
)

// TextToolWaiting is the status the caller sees while a tool request waits for the owner.
const TextToolWaiting = "waiting for the owner's approval of a tool call"

const protocolVersion = 1

const (
	typeTask     = "task"
	typeAnswer   = "answer"
	typeCancel   = "cancel"
	typeStatus   = "status"
	typeQuestion = "question"
	typeResult   = "result"
	typeError    = "error"
	typeTool     = "tool"
	typeToolRes  = "tool_result"
)

var (
	errProtocol = errors.New("adapter: the bot broke the line protocol")
	errTooLong  = errors.New("adapter: a line from the bot is too long")
)

// toBot is a line sent to the bot. Content is added by encode so its buffer is
// ours to scrub.
type toBot struct {
	V       int    `json:"v"`
	Type    string `json:"type"`
	ID      string `json:"id"`
	Turn    int    `json:"turn,omitempty"`
	Context string `json:"context,omitempty"`
	Caller  string `json:"caller,omitempty"`
	Owner   string `json:"owner,omitempty"`
	Expires string `json:"expires,omitempty"`
	// The fields of a tool_result: what became of the request, never more than that.
	Outcome   string `json:"outcome,omitempty"`
	Exit      int    `json:"exit,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Untrusted bool   `json:"untrusted,omitempty"` // the content is output of a tool: data, not instructions
}

// encode renders one line, newline included. The caller clears it when the
// line has been written.
func encode(h toBot, content []byte, withContent bool) []byte {
	head, _ := json.Marshal(h) // a struct of strings and ints cannot fail
	const key = `,"content":"`
	n := len(head) + 1 // the head without its closing brace, then the brace and the newline
	if withContent {
		n += len(key) + base64.StdEncoding.EncodedLen(len(content)) + 1
	}
	out := make([]byte, 0, n)
	out = append(out, head[:len(head)-1]...)
	if withContent {
		out = append(out, key...)
		out = base64.StdEncoding.AppendEncode(out, content)
		out = append(out, '"')
	}
	return append(out, '}', '\n')
}

func taskLine(t bot.Task) []byte {
	return encode(toBot{V: protocolVersion, Type: typeTask, ID: hex.EncodeToString(t.ID[:]), Context: t.Context,
		Caller: t.Caller, Owner: t.Owner, Expires: t.Expiry.UTC().Format(time.RFC3339)}, t.Content, true)
}

func answerLine(id [16]byte, turn int, content []byte) []byte {
	return encode(toBot{V: protocolVersion, Type: typeAnswer, ID: hex.EncodeToString(id[:]), Turn: turn}, content, true)
}

func toolResultLine(id [16]byte, turn int, r ToolReply) []byte {
	return encode(toBot{V: protocolVersion, Type: typeToolRes, ID: hex.EncodeToString(id[:]), Turn: turn, Outcome: r.Outcome,
		Exit: r.Exit, Truncated: r.Truncated, Untrusted: true}, r.Content, true)
}

func cancelLine(id [16]byte) []byte {
	return encode(toBot{V: protocolVersion, Type: typeCancel, ID: hex.EncodeToString(id[:])}, nil, false)
}

// message is a line from the bot.
type message struct {
	Type    string   `json:"type"`
	Content []byte   `json:"content"`
	Message string   `json:"message"`
	Tool    string   `json:"tool"`
	Args    []string `json:"args"`
}

// readMessage reads and validates one line, refusing one longer than MaxLine
// without buffering more than that.
func readMessage(r *bufio.Reader) (message, error) {
	var line []byte
	for {
		part, more, err := r.ReadLine()
		if err != nil {
			return message{}, err
		}
		if len(line)+len(part) > MaxLine {
			return message{}, errTooLong
		}
		line = append(line, part...)
		if !more {
			break
		}
	}
	// Strict: unknown fields, trailing data and a second value are protocol errors, not ignored input.
	var m message
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if dec.Decode(&m) != nil || dec.More() {
		return message{}, errProtocol
	}
	switch m.Type {
	case typeStatus, typeQuestion, typeResult, typeError:
		if m.Tool == "" && m.Args == nil {
			return m, nil
		}
	case typeTool: // a request carries a tool and arguments only
		if m.Content == nil && m.Message == "" && len(m.Args) <= MaxToolArgs {
			return m, nil
		}
	}
	return message{}, errProtocol
}

// peer is the bot as seen by converse: a stream of its messages and a way to
// give it the caller's answer.
type peer interface {
	next() (message, error)
	answer(ctx context.Context, turn int, content []byte) error
}

// Tools runs the tools a bot asks for. Call returns an error only when ctx ends; any other result is in the reply.
// onWait is called if the request has to wait for the owner. End is called once, when the task is over.
type Tools interface {
	Call(ctx context.Context, t bot.Task, tool string, args []string, onWait func()) (ToolReply, error)
	End(task [16]byte)
}

// ToolReply is what the bot is told about a tool request. Content is untrusted output, already framed.
type ToolReply struct {
	Outcome   string
	Exit      int
	Truncated bool
	Content   []byte
}

// toolConv is what converse needs to serve tool requests; it is nil for a bot that may not make any.
type toolConv struct {
	tools Tools
	task  bot.Task
	send  func(ctx context.Context, line []byte) error
}

// converse drives one task: status goes to the caller as it comes, a question is
// put to the caller and its answer handed back, a tool request goes to tc and
// its reply back to the bot, and the first result or error ends it. A bot that
// talks too much, asks for a tool without tc, or ends without a final message fails.
func converse(ctx context.Context, p peer, s bot.Session, tc *toolConv) ([]byte, error) {
	statuses, questions, requests := 0, 0, 0
	for {
		m, err := p.next()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		switch m.Type {
		case typeStatus:
			if statuses++; statuses > MaxStatuses {
				return nil, errProtocol
			}
			if err := s.Status(ctx, m.Content); err != nil {
				return nil, err
			}
		case typeQuestion:
			if questions++; questions > MaxQuestions {
				return nil, errProtocol
			}
			a, err := s.Ask(ctx, m.Content)
			if err != nil {
				return nil, err
			}
			err = p.answer(ctx, questions, a)
			clear(a)
			if err != nil {
				return nil, err
			}
		case typeTool:
			if tc == nil {
				return nil, errProtocol
			}
			if requests++; requests > MaxToolRequests {
				return nil, errProtocol
			}
			r, err := tc.tools.Call(ctx, tc.task, m.Tool, m.Args, func() { _ = s.Status(ctx, []byte(TextToolWaiting)) })
			if err != nil {
				return nil, err
			}
			err = tc.send(ctx, toolResultLine(tc.task.ID, requests, r))
			clear(r.Content) // the output of a tool is task data: no copy of ours outlives its use
			if err != nil {
				return nil, err
			}
		case typeResult:
			return m.Content, nil
		default: // typeError: readMessage admits nothing else
			return nil, &bot.Failure{Message: m.Message}
		}
	}
}
