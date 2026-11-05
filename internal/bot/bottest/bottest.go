// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package bottest is the adapter contract made executable: a scripted Fake bot
// and Contract, the suite every adapter (T402) must pass. The script travels in
// the task content, so an adapter that forwards content to a real process or
// service can be tested against a Fake served behind it.
//
// Scripts (the content of the task is the script, a verb and an argument):
//
//	echo X     result "echo X"
//	status X   status "X", then result "done"
//	ask X      question "X", result "answer: <the caller's answer>"
//	fail X     Failure "X"
//	leak X     plain error carrying X (the caller must never see X)
//	panic X    panic carrying X (the caller must never see X)
//	block      wait until the context ends, then return its error
//	big        a result larger than the pipeline allows
package bottest

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// Fake is a scripted bot. Started receives each task's ID as it begins, for
// tests that need to know a bot is running.
type Fake struct {
	Started chan [16]byte
}

func (f *Fake) Handle(ctx context.Context, t bot.Task, s bot.Session) ([]byte, error) {
	if f.Started != nil {
		select {
		case f.Started <- t.ID:
		default:
		}
	}
	verb, arg, _ := strings.Cut(string(t.Content), " ")
	switch verb {
	case "echo":
		return []byte("echo " + arg), nil
	case "status":
		if err := s.Status(ctx, []byte(arg)); err != nil {
			return nil, err
		}
		return []byte("done"), nil
	case "ask":
		a, err := s.Ask(ctx, []byte(arg))
		if err != nil {
			return nil, err
		}
		return append([]byte("answer: "), a...), nil
	case "fail":
		return nil, &bot.Failure{Message: arg}
	case "leak":
		return nil, errors.New(arg)
	case "panic":
		panic(arg)
	case "block":
		<-ctx.Done()
		return nil, ctx.Err()
	case "big":
		return bytes.Repeat([]byte("x"), pipeline.MaxContent+1), nil
	}
	return nil, &bot.Failure{Message: "unknown script"}
}
