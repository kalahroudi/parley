// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package bottest

import (
	"context"
	"sync"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// Message is one thing the bot's host sent to the caller.
type Message struct {
	ID      [16]byte
	Type    envelope.Type
	Content string
}

// Recorder is a bot.Responder that records what it is given. It enforces the
// pipeline's rule that a task ends with one final message: later messages for an
// ended task fail with pipeline.ErrState, as the real pipeline does. Oversized
// content is refused as the pipeline refuses it.
type Recorder struct {
	mu    sync.Mutex
	msgs  []Message
	ended map[[16]byte]bool
	wake  chan struct{}
}

func NewRecorder() *Recorder {
	return &Recorder{ended: map[[16]byte]bool{}, wake: make(chan struct{}, 1)}
}

func (r *Recorder) Respond(_ context.Context, id [16]byte, typ envelope.Type, content []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(content) > pipeline.MaxContent {
		return pipeline.ErrState
	}
	if r.ended[id] {
		return pipeline.ErrState
	}
	if typ != envelope.TypeStatus && typ != envelope.TypeInputRequired {
		r.ended[id] = true
	}
	r.msgs = append(r.msgs, Message{ID: id, Type: typ, Content: string(content)})
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

// Messages returns what was sent for one task, in order.
func (r *Recorder) Messages(id [16]byte) []Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Message
	for _, m := range r.msgs {
		if m.ID == id {
			out = append(out, m)
		}
	}
	return out
}

// Wait blocks until n messages for the task were sent, or the context ends.
func (r *Recorder) Wait(ctx context.Context, id [16]byte, n int) []Message {
	for {
		if m := r.Messages(id); len(m) >= n {
			return m
		}
		select {
		case <-r.wake:
		case <-ctx.Done():
			return r.Messages(id)
		}
	}
}
