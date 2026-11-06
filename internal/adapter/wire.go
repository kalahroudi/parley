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
)

const protocolVersion = 1

const (
	typeTask     = "task"
	typeAnswer   = "answer"
	typeCancel   = "cancel"
	typeStatus   = "status"
	typeQuestion = "question"
	typeResult   = "result"
	typeError    = "error"
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

func cancelLine(id [16]byte) []byte {
	return encode(toBot{V: protocolVersion, Type: typeCancel, ID: hex.EncodeToString(id[:])}, nil, false)
}

// message is a line from the bot.
type message struct {
	Type    string `json:"type"`
	Content []byte `json:"content"`
	Message string `json:"message"`
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
		return m, nil
	}
	return message{}, errProtocol
}

// peer is the bot as seen by converse: a stream of its messages and a way to
// give it the caller's answer.
type peer interface {
	next() (message, error)
	answer(ctx context.Context, turn int, content []byte) error
}

// converse drives one task: status goes to the caller as it comes, a question is
// put to the caller and its answer handed back, and the first result or error
// ends it. A bot that talks too much or ends without a final message fails.
func converse(ctx context.Context, p peer, s bot.Session) ([]byte, error) {
	statuses, questions := 0, 0
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
		case typeResult:
			return m.Content, nil
		default: // typeError: readMessage admits nothing else
			return nil, &bot.Failure{Message: m.Message}
		}
	}
}
