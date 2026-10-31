// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package logx is the only way Parley code writes logs. It accepts four kinds
// of field and nothing else: identifiers, state codes, sizes and timestamps.
// There is deliberately no constructor for a free-form string, so task
// content (inputs, results, status text, questions, errors, file names) cannot
// be logged by accident. Values are checked again at runtime, so a payload
// smuggled into an id or state slot is replaced with a placeholder.
package logx

import (
	"context"
	"io"
	"log/slog"
	"time"
)

// Redacted replaces any value that fails validation.
const Redacted = "[redacted]"

// maxIDLen bounds identifiers (a 128-bit task id is 32 hex characters).
const maxIDLen = 64

// Keys is the allowlist of field names.
var Keys = map[string]bool{
	"tenant": true, "device": true, "bot": true, "task": true, "context": true,
	"prekey": true, "request": true, "seq": true,
	"state": true, "type": true, "retention": true,
	"size": true, "bucket": true, "count": true,
	"at": true, "issued_at": true, "expires_at": true, "deadline": true,
}

// States is the allowlist of state and message-type codes.
var States = map[string]bool{
	"TASK_STATE_SUBMITTED": true, "TASK_STATE_WORKING": true,
	"TASK_STATE_INPUT_REQUIRED": true, "TASK_STATE_COMPLETED": true,
	"TASK_STATE_FAILED": true, "TASK_STATE_CANCELED": true,
	"TASK_STATE_REJECTED": true,
	"TASK":                true, "STATUS": true, "INPUT_REQUIRED": true, "RESULT": true,
	"ERROR": true, "CANCEL": true,
	"strict": true, "queued": true,
}

// Field is one log attribute. It can only be built by ID, State, Size or Time.
type Field struct{ attr slog.Attr }

// ID logs an opaque identifier: 1..64 characters of [A-Za-z0-9_-] (device,
// task and prekey ids, hex hashes). Anything else is redacted.
func ID(key, v string) Field { return mk(key, slog.StringValue(safeID(v))) }

// State logs a state code or message type from States; anything else is redacted.
func State(key, v string) Field {
	if !States[v] {
		v = Redacted
	}
	return mk(key, slog.StringValue(v))
}

// Size logs a byte or item count. Negative values are logged as -1.
func Size(key string, n int64) Field {
	if n < 0 {
		n = -1
	}
	return mk(key, slog.Int64Value(n))
}

// Time logs a timestamp in UTC, second resolution.
func Time(key string, t time.Time) Field {
	return mk(key, slog.StringValue(t.UTC().Truncate(time.Second).Format(time.RFC3339)))
}

func mk(key string, v slog.Value) Field {
	if !Keys[key] {
		key = "badkey"
		v = slog.StringValue(Redacted)
	}
	return Field{slog.Attr{Key: key, Value: v}}
}

func safeID(s string) string {
	if s == "" || len(s) > maxIDLen {
		return Redacted
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return Redacted
		}
	}
	return s
}

// Logger writes redacted structured logs.
type Logger struct{ l *slog.Logger }

// Msg is a log message. Untyped string constants convert to it implicitly,
// but a string variable does not, so a message cannot be built at run time
// from task data without an explicit (and reviewable) conversion.
type Msg string

// New returns a logger that writes text lines to w.
func New(w io.Writer) *Logger {
	return &Logger{slog.New(slog.NewTextHandler(w, nil))}
}

// Info logs msg with fields.
func (l *Logger) Info(msg Msg, f ...Field) { l.log(slog.LevelInfo, msg, f) }

// Warn logs msg with fields.
func (l *Logger) Warn(msg Msg, f ...Field) { l.log(slog.LevelWarn, msg, f) }

// Error logs msg with fields. Never log err.Error(): error text can embed task
// content. Log a State and an ID instead.
func (l *Logger) Error(msg Msg, f ...Field) { l.log(slog.LevelError, msg, f) }

func (l *Logger) log(lvl slog.Level, msg Msg, f []Field) {
	attrs := make([]slog.Attr, len(f))
	for i, x := range f {
		attrs[i] = x.attr
	}
	l.l.LogAttrs(context.Background(), lvl, string(msg), attrs...)
}
