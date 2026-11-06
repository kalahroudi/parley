// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package adaptertest is test support for the adapters: the reference side of
// "parley-bot/1", which runs any bot.Bot behind the line protocol, for the
// adapter tests to serve over HTTP (or another transport). No shipped program
// may link it.
package adaptertest

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/kalahroudi/parley/internal/bot"
)

// InLine is a line the adapter sends.
type InLine struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Turn    int    `json:"turn"`
	Context string `json:"context"`
	Caller  string `json:"caller"`
	Owner   string `json:"owner"`
	Expires string `json:"expires"`
	Content []byte `json:"content"`
}

// OutLine is a line the bot sends.
type OutLine struct {
	Type    string `json:"type"`
	Content []byte `json:"content,omitempty"`
	Message string `json:"message,omitempty"`
}

// Conv is one task running in a reference bot: Out carries its lines (closed
// when it is over) and Answers takes the caller's answers.
type Conv struct {
	Out     chan OutLine
	Answers chan []byte
	Cancel  context.CancelFunc
	ctx     context.Context
}

func (c *Conv) emit(o OutLine) error {
	select {
	case c.Out <- o:
		return nil
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
}

type session struct{ c *Conv }

func (s session) Status(_ context.Context, text []byte) error {
	return s.c.emit(OutLine{Type: "status", Content: append([]byte(nil), text...)})
}

func (s session) Ask(ctx context.Context, q []byte) ([]byte, error) {
	if err := s.c.emit(OutLine{Type: "question", Content: append([]byte(nil), q...)}); err != nil {
		return nil, err
	}
	select {
	case a := <-s.c.Answers:
		return a, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Start runs b on the task in in.
func Start(b bot.Bot, in InLine) *Conv {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Conv{Out: make(chan OutLine), Answers: make(chan []byte, 1), Cancel: cancel, ctx: ctx}
	id, _ := hex.DecodeString(in.ID)
	t := bot.Task{Context: in.Context, Caller: in.Caller, Owner: in.Owner, Content: in.Content}
	copy(t.ID[:], id)
	t.Expiry, _ = time.Parse(time.RFC3339, in.Expires)
	go func() {
		defer close(c.Out)
		defer cancel()
		res, err := func() (res []byte, err error) {
			defer func() {
				if recover() != nil {
					err = errors.New("panic")
				}
			}()
			return b.Handle(ctx, t, session{c})
		}()
		var f *bot.Failure
		switch {
		case ctx.Err() != nil:
			return
		case err == nil:
			c.emit(OutLine{Type: "result", Content: res})
		case errors.As(err, &f):
			c.emit(OutLine{Type: "error", Message: f.Message})
		default:
			c.emit(OutLine{Type: "error", Message: bot.TextFailed}) // a service says nothing of what went wrong inside
		}
	}()
	return c
}

// WriteLine writes one bot line.
func WriteLine(w io.Writer, o OutLine) {
	b, _ := json.Marshal(o)
	w.Write(append(b, '\n'))
}

// ServeStdio runs b as a CLI bot: it reads the task line from in, writes the bot's lines to out and hands the
// answer lines that follow to the bot. The task is canceled when in ends, as when the adapter closes the pipe. It
// returns when the task is over; its reader goroutine ends when in does.
func ServeStdio(b bot.Bot, in io.Reader, out io.Writer) {
	r := bufio.NewReaderSize(in, 1<<20)
	var first InLine
	line, err := r.ReadBytes('\n')
	if err != nil || json.Unmarshal(line, &first) != nil {
		return
	}
	c := Start(b, first)
	defer c.Cancel()
	go func() {
		for {
			line, err := r.ReadBytes('\n')
			var a InLine
			if err != nil || json.Unmarshal(line, &a) != nil {
				c.Cancel()
				return
			}
			select {
			case c.Answers <- a.Content:
			case <-c.ctx.Done():
				return
			}
		}
	}()
	for o := range c.Out {
		WriteLine(out, o)
	}
}
