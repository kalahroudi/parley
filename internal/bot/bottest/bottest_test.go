// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package bottest_test

import (
	"context"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/bot/bottest"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/pipeline"
)

func TestFakeMeetsContract(t *testing.T) {
	bottest.Contract(t, func(*testing.T) bot.Bot { return &bottest.Fake{} })
}

func TestFakeStartedAndUnknownScript(t *testing.T) {
	f := &bottest.Fake{Started: make(chan [16]byte, 1)}
	_, err := f.Handle(context.Background(), bot.Task{ID: [16]byte{4}, Content: []byte("nope")}, nil)
	if fl, ok := err.(*bot.Failure); !ok || fl.Message != "unknown script" {
		t.Fatal(err)
	}
	if <-f.Started != ([16]byte{4}) {
		t.Fatal("Started")
	}
}

func TestFakeStatusFailureAndRecorderRules(t *testing.T) {
	f := &bottest.Fake{}
	if _, err := f.Handle(context.Background(), bot.Task{Content: []byte("status x")}, failStatus{}); err != pipeline.ErrState {
		t.Fatal(err)
	}
	r := bottest.NewRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	id := [16]byte{1}
	if err := r.Respond(ctx, id, envelope.TypeResult, nil); err != nil {
		t.Fatal(err)
	}
	if r.Respond(ctx, id, envelope.TypeStatus, nil) != pipeline.ErrState {
		t.Fatal("message after the final one accepted")
	}
	if r.Respond(ctx, [16]byte{2}, envelope.TypeResult, make([]byte, pipeline.MaxContent+1)) != pipeline.ErrState {
		t.Fatal("oversized content accepted")
	}
	if got := r.Wait(ctx, id, 2); len(got) != 1 {
		t.Fatal("Wait should return what exists when the context ends")
	}
}

type failStatus struct{}

func (failStatus) Status(context.Context, []byte) error { return pipeline.ErrState }
func (failStatus) Ask(context.Context, []byte) ([]byte, error) {
	return nil, pipeline.ErrState
}
