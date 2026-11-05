// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package bot is the contract between the daemon and the bot a customer brings.
// An adapter (T402: API, headless CLI, ACP) implements Bot; Host runs it behind
// the pipeline's callbacks and owns everything the daemon promises about a task,
// so adapters stay small and cannot get it wrong:
//
//   - the plaintext reaches the bot only from Host, after the pipeline has
//     opened, verified, erased the key and acknowledged (pipeline.Inbound);
//   - at most Config.MaxRunning tasks run and Config.MaxQueued wait; the rest are
//     answered with a fixed ERROR ("busy") and never reach the bot;
//   - every accepted task ends in exactly one final message: RESULT, ERROR or the
//     CANCEL acknowledgment. A bot that panics, errs or runs out of time ends in
//     ERROR with a fixed or bot-declared Failure text, never an arbitrary error
//     string (which may hold task content);
//   - the context handed to the bot is canceled on CANCEL from the caller, on the
//     task's expiry, on Config.Timeout and on Host.Close; the bot must return
//     promptly when it is, and Host does not wait for a bot that does not;
//   - the task's content buffer is zeroed when Handle returns, so a bot must copy
//     what it keeps (and the customer's bot keeps it outside our guarantee).
//
// What this package does not do: it holds no plaintext beyond a task's run, logs
// nothing and writes nothing to disk. It cannot stop a bot from keeping or
// leaking what it was given.
package bot

import (
	"context"
	"errors"
	"time"
)

// Task is one task for the bot. Content (and Context, Caller, Owner) is valid
// only during Handle; Caller and Owner come from the caller's root-signed
// binding and are what the bot may use to tell callers apart.
type Task struct {
	ID      [16]byte
	Context string
	Caller  string
	Owner   string
	Content []byte
	Expiry  time.Time
}

// Session is the bot's side channel for one task. It is valid until Handle
// returns, after which every call fails with ErrClosed.
type Session interface {
	// Status sends encrypted status text to the caller.
	Status(ctx context.Context, text []byte) error
	// Ask sends a question (INPUT_REQUIRED) and blocks for the caller's answer on
	// the same task. It fails with the context's error if the task ends first.
	Ask(ctx context.Context, question []byte) ([]byte, error)
}

// Bot is what an adapter implements. Handle runs one task to completion and
// returns the result, or an error (a Failure's Message reaches the caller, any
// other error becomes a fixed message). It is called concurrently for different
// tasks and must be safe for that.
type Bot interface {
	Handle(ctx context.Context, t Task, s Session) ([]byte, error)
}

// Failure is an error whose Message is meant for the caller, sent as the ERROR
// content (cut to MaxFailure bytes). Put no task content or secrets in it.
type Failure struct{ Message string }

func (f *Failure) Error() string { return f.Message }

// Fixed texts the caller sees when the bot gave none, and the limits on them.
const (
	MaxFailure   = 1 << 10
	TextBusy     = "rejected: the bot is busy"
	TextFailed   = "the bot failed"
	TextTimedOut = "the bot timed out"
	TextTooLarge = "the result is too large"
)

var (
	ErrClosed = errors.New("bot: the task has ended")
	ErrConfig = errors.New("bot: incomplete configuration")
)
