// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package logx

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const canary = "CANARY-secret payload\n"

func TestFieldsAllowed(t *testing.T) {
	var b bytes.Buffer
	l := New(&b)
	at := time.Date(2026, 1, 2, 3, 4, 5, 999, time.FixedZone("x", 3600))
	l.Info("task received",
		ID("task", "0123456789abcdef0123456789abcdef"),
		ID("device", "dev_A-1"),
		State("state", "TASK_STATE_WORKING"),
		State("type", "RESULT"),
		Size("size", 4096),
		Time("at", at))
	l.Warn("w")
	l.Error("e", Size("count", 1))
	out := b.String()
	for _, want := range []string{
		"task=0123456789abcdef0123456789abcdef", "device=dev_A-1",
		"state=TASK_STATE_WORKING", "type=RESULT", "size=4096",
		"at=2026-01-02T02:04:05Z", "level=WARN", "level=ERROR",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}

func TestPayloadsRedacted(t *testing.T) {
	var b bytes.Buffer
	l := New(&b)
	l.Info("x",
		ID("task", canary),                 // not an id
		ID("device", ""),                   // empty
		ID("bot", strings.Repeat("a", 65)), // too long
		State("state", canary),             // not a state
		Size("size", -5),
		ID("input", "abc"), // key not allowlisted
		State("result", "TASK"),
		Size("text", 1),
		Time("filename", time.Unix(0, 0)))
	out := b.String()
	if strings.Contains(out, "CANARY") || strings.Contains(out, "secret") {
		t.Fatalf("payload leaked: %q", out)
	}
	for _, want := range []string{"task=[redacted]", "device=[redacted]", "bot=[redacted]", "state=[redacted]", "size=-1", "badkey=[redacted]"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	for _, k := range []string{"input=", "result=", "text=", "filename="} {
		if strings.Contains(out, k) {
			t.Errorf("non-allowlisted key %q logged: %q", k, out)
		}
	}
}

func TestZeroTimeNilLoggerAndLevel(t *testing.T) {
	var b bytes.Buffer
	New(&b).Info("z", Time("at", time.Time{}))
	if !strings.Contains(b.String(), "at=unset") {
		t.Errorf("zero time: %q", b.String())
	}
	var nilLogger *Logger
	nilLogger.Info("x", Size("size", 1)) // must not panic
	nilLogger.Error("x")
	b.Reset()
	l := NewLevel(&b, slog.LevelWarn)
	l.Info("hidden")
	l.Warn("shown")
	if strings.Contains(b.String(), "hidden") || !strings.Contains(b.String(), "shown") {
		t.Errorf("level not applied: %q", b.String())
	}
}

func TestKeysAreNotPayloadNames(t *testing.T) {
	for k := range Keys {
		if _, bad := payloadNames[k]; bad {
			t.Errorf("allowlisted key %q looks like a payload field", k)
		}
	}
}

// The edges of each rule: zero is a size, 64 characters is an identifier and 65
// is not, and the first and last character of every allowed class pass.
func TestBoundaries(t *testing.T) {
	var b bytes.Buffer
	l := New(&b)
	for n, want := range map[int64]string{0: "size=0", -5: "size=-1", 1: "size=1"} {
		b.Reset()
		l.Info("sizes", Size("size", n))
		if !strings.Contains(b.String(), want) {
			t.Errorf("Size(%d): missing %q in %q", n, want, b.String())
		}
	}
	for _, id := range []string{strings.Repeat("a", maxIDLen), "a", "z", "A", "Z", "0", "9", "-", "_"} {
		if got := safeID(id); got != id {
			t.Errorf("safeID(%q) = %q", id, got)
		}
	}
	for _, id := range []string{"", strings.Repeat("a", maxIDLen+1), "`", "{", "@", "[", "/", ":", "."} {
		if got := safeID(id); got != Redacted {
			t.Errorf("safeID(%q) = %q, want redacted", id, got)
		}
	}
}

func TestParseLevel(t *testing.T) {
	for name, want := range map[string]slog.Level{
		"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn,
		"error": slog.LevelError, "": slog.LevelInfo, "trace": slog.LevelInfo,
	} {
		if got := ParseLevel(name); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", name, got, want)
		}
	}
}
