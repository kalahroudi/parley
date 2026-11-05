// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/kalahroudi/parley/internal/caller"
	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/mcp"
)

// defaultTestTimeout bounds `parley-cli test` unless -timeout says otherwise: long enough for a target that is
// just starting, short enough for someone watching the terminal.
const (
	defaultTestTimeout = 30 * time.Second
	startGrace         = 10 * time.Second // how long a not_ready answer is taken to mean "still starting"
)

// selfTest sends one task with a fresh random text to another of the user's own devices, whose daemon runs the
// built-in test bot, and checks that the sealed answer is the expected echo. A pass proves the whole path:
// this daemon's enrollment and trust state, the gateway, the other daemon, the prekey exchange, both
// directions of the sealed transport, and the bot. Nothing but the random text is sent.
func (s *session) selfTest(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(s.errw)
	to := fs.String("to", "", "device id of another of your devices (shown by `parley-cli enroll` on it)")
	timeout := fs.Duration("timeout", defaultTestTimeout, "give up after this long")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *to == "" {
		fmt.Fprintln(s.errw, "usage: parley-cli test -to <device id> [-timeout 30s]")
		return 2
	}
	secs, ok := s.seconds("timeout", *timeout)
	if !ok || secs < int64(caller.MinExpiry/time.Second) || secs > int64(caller.DefaultExpiry/time.Second) {
		fmt.Fprintln(s.errw, "error: -timeout must be between 5s and 15m")
		return 2
	}
	src := s.rand
	if src == nil {
		src = rand.Reader
	}
	var nonce [16]byte
	if _, err := io.ReadFull(src, nonce[:]); err != nil {
		fmt.Fprintln(s.errw, "error: no randomness for the test text")
		return 1
	}
	text := "parley-test " + hex.EncodeToString(nonce[:])
	now := s.now
	if now == nil {
		now = time.Now
	}
	start := now()

	// A daemon that has just started has not fetched its revocation list yet and fails a send with not_ready; that
	// clears within moments, so for a short while the test sends again instead of reporting it.
	deadline := start.Add(*timeout)
	var v caller.View
	for {
		left := deadline.Sub(now())
		if left < caller.MinExpiry || ctx.Err() != nil {
			fmt.Fprintln(s.errw, "FAIL: no answer in time")
			return 1
		}
		var code string
		if v, code = s.testTask(ctx, *to, text, left, deadline.Add(2*time.Second), now); code != "" {
			return s.testFailed(code)
		}
		if v.State != caller.Failed || v.Reason != caller.ReasonNotReady || now().Sub(start) > startGrace {
			break
		}
		s.pause(ctx, time.Second)
	}
	if !final(v.State) {
		fmt.Fprintln(s.errw, "FAIL: no answer in time")
		return 1
	}
	switch {
	case v.State == caller.Completed && v.Kind == caller.KindResult && v.Content == daemon.TestBotPrefix+text:
		fmt.Fprintf(s.out, "PASS: the other device answered, end to end encrypted, in %s.\n", now().Sub(start).Round(time.Millisecond))
		return 0
	case v.State == caller.Completed:
		fmt.Fprintln(s.errw, "FAIL: the answer was not the expected echo (is that device running a bot of its own?)")
	default:
		fmt.Fprintf(s.errw, "FAIL: the task ended as %s (%s). %s\n", v.State, mcp.SafeCode(v.Reason), reasonHint(v.Reason))
	}
	return 1
}

// testTask sends one task and waits until it is final or the deadline passes. The returned view is the last one
// seen; the code is the daemon's fixed error code when it could not be asked.
func (s *session) testTask(ctx context.Context, to, text string, expiry time.Duration, deadline time.Time, now func() time.Time) (caller.View, string) {
	var v caller.View
	if code, ok := s.rpc(ctx, "send_task", caller.SendParams{Agent: to, Text: text, ExpirySeconds: int64(expiry / time.Second)}, &v); !ok {
		return v, code
	}
	fmt.Fprintln(s.out, "Sent an encrypted test task; waiting for the answer.")
	for !final(v.State) {
		left := deadline.Sub(now())
		if left <= 0 || ctx.Err() != nil {
			return v, ""
		}
		wait := min(int64((left+time.Second-1)/time.Second), int64(caller.MaxWait/time.Second))
		if code, ok := s.rpc(ctx, "get_task", caller.GetParams{TaskID: v.ID, WaitSeconds: wait}, &v); !ok {
			return v, code
		}
	}
	return v, ""
}

// pause waits d, or until ctx ends.
func (s *session) pause(ctx context.Context, d time.Duration) {
	if s.sleep != nil {
		s.sleep(d)
		return
	}
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

func final(state string) bool {
	switch state {
	case caller.Completed, caller.Failed, caller.Canceled, caller.Rejected:
		return true
	}
	return false
}

// rpc calls a daemon method and decodes its result; on failure it returns the daemon's fixed error code.
func (s *session) rpc(ctx context.Context, method string, params, out any) (string, bool) {
	resp, err := s.call(ctx, method, params)
	switch {
	case err != nil:
		return "unreachable", false
	case !resp.OK:
		return mcp.SafeCode(resp.Error), false
	}
	if json.Unmarshal(resp.Result, out) != nil {
		return "internal", false
	}
	return "", true
}

func (s *session) testFailed(code string) int {
	switch code {
	case "unreachable":
		fmt.Fprintln(s.errw, "FAIL: the Parley daemon is not running or not reachable (start parleyd)")
	case caller.CodeNotReady:
		fmt.Fprintln(s.errw, "FAIL: this device is not enrolled yet or its daemon is still starting (parley-cli enroll, then parleyd)")
	case caller.CodeBadParams:
		fmt.Fprintln(s.errw, "FAIL: that is not a device id")
	default:
		fmt.Fprintln(s.errw, "FAIL: the daemon refused the test:", code)
	}
	return 1
}

// reasonHint is what to do about a reason the daemon reports (fixed codes, never text from the other side).
func reasonHint(reason string) string {
	switch reason {
	case caller.ReasonOffline, caller.ReasonExpired:
		return "The other device was not reachable: is its parleyd running?"
	case caller.ReasonGone:
		return "The gateway does not know that device (wrong id, not approved, or revoked)."
	case caller.ReasonNotAllowed, caller.ReasonRefused:
		return "The other device refused: the test bot answers only devices of its own owner."
	case caller.ReasonNotReady:
		return "Enroll this device and start parleyd first."
	}
	return ""
}
