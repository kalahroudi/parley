// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package approval is the owner's approval for tasks a bot would act on (journey
// G). A Gate wraps a bot.Bot. In mode "owner" a task does not reach the bot
// until the owner approves it with `parley-cli approve <id>`; a denial, or no
// answer within the timeout (5 minutes), ends the task with a fixed "rejected"
// error and the bot never sees it. In mode "none" the Gate is transparent.
//
// What this guarantees, exactly:
//
//   - The bot's Handle is called only after an approval for that task id was
//     recorded, and at most once per task. The decision is taken once, under a
//     lock: approve after a denial, after the timeout or after the task ended is
//     refused with "not_found", and so is a second approve.
//   - Every wait ends: by decision, by timeout, or with the task's context (the
//     caller's CANCEL, the task's expiry, shutdown). Nothing is left pending.
//   - At most MaxPending tasks (MaxPerCaller from one caller device or owner) wait
//     for approval; the rest are rejected at once, so an allowed caller cannot
//     fill the daemon with tasks that wait for a person.
//   - The caller sees only fixed texts (no task content, no owner identity).
//   - What the owner sees is the caller, its owner, the times and a bounded
//     preview of the task, with control and formatting characters replaced, so
//     task text cannot rewrite the owner's terminal. The preview is held in memory
//     until the decision and zeroed.
//
// What it does not guarantee: the socket is open to every process of the same OS
// user (see internal/localsock), so a bot that runs as the owner and can reach the
// socket can approve its own tasks. Keeping tool-using skills away from the socket
// is the sandbox's job (T406, T507); until then the approval is a confirmation
// for the owner, not a boundary against code running as the owner.
package approval

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/localsock"
)

// Mode is a bot's approval mode.
type Mode string

const (
	// None runs every task that passed the allowlist (tool-less skills).
	None Mode = "none"
	// Owner holds each task until the owner approves it.
	Owner Mode = "owner"
)

// Limits, as single literals so that the mutation gate can cover them
// (TestConstantsArePinned pins them).
const (
	DefaultTimeout      = time.Duration(300e9) // 5 minutes, the spec's "no answer in 5 min"
	DefaultMaxPending   = 16
	DefaultMaxPerCaller = 4
	MaxPreview          = 512 // bytes of the task shown to the owner
	maxIdentity         = 128 // bytes of a caller or owner name shown
)

// What the caller sees. The first is a status while the task waits; the others
// end the task.
const (
	TextWaiting   = "waiting for the owner's approval"
	TextDenied    = "rejected: the owner did not approve the task"
	TextTimedOut  = "rejected: no approval within the time allowed"
	TextTooMany   = "rejected: too many tasks are waiting for approval"
	TextDuplicate = "rejected: a task with this id is already waiting for approval"
)

// Error codes the owner's commands receive (fixed identifiers).
const (
	CodeBadParams = "bad_params"
	CodeNotFound  = "not_found"
)

// ErrConfig is returned by New for a missing bot or an unknown mode.
var ErrConfig = errors.New("approval: incomplete configuration")

// ErrNotPending means no task with that id is waiting: it never was, it was
// already decided, it timed out or it ended.
var ErrNotPending = errors.New("approval: no such task is waiting")

// Config sets a Gate. Zero values take the defaults.
type Config struct {
	Bot          bot.Bot
	Mode         Mode // default None
	Timeout      time.Duration
	MaxPending   int
	MaxPerCaller int
	Now          func() time.Time
}

// Gate is a bot.Bot that asks the owner first.
type Gate struct {
	cfg Config

	mu      sync.Mutex
	waiting map[[16]byte]*entry
}

type decision int

const (
	approved decision = 1
	denied   decision = 2
	timedOut decision = 3
)

type entry struct {
	id       [16]byte
	caller   string
	owner    string
	preview  []byte
	more     bool // the task is longer than the preview
	received time.Time
	deadline time.Time
	decided  bool
	result   chan decision // buffered: the deciding side never blocks
}

// New builds a Gate.
func New(cfg Config) (*Gate, error) {
	if cfg.Bot == nil {
		return nil, ErrConfig
	}
	switch cfg.Mode {
	case "":
		cfg.Mode = None
	case None, Owner:
	default:
		return nil, ErrConfig
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = DefaultMaxPending
	}
	if cfg.MaxPerCaller <= 0 {
		cfg.MaxPerCaller = DefaultMaxPerCaller
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Gate{cfg: cfg, waiting: map[[16]byte]*entry{}}, nil
}

// Handle implements bot.Bot.
func (g *Gate) Handle(ctx context.Context, t bot.Task, s bot.Session) ([]byte, error) {
	if g.cfg.Mode == None {
		return g.cfg.Bot.Handle(ctx, t, s)
	}
	e, why := g.enter(t)
	if why != "" {
		return nil, &bot.Failure{Message: why}
	}
	defer g.leave(e)
	// Best effort: the caller learns the task is waiting for a person. If the
	// send fails the task is ending anyway, and the wait below sees its context.
	_ = s.Status(ctx, []byte(TextWaiting))
	timer := time.NewTimer(g.cfg.Timeout)
	defer timer.Stop()
	var d decision
	select {
	case d = <-e.result:
	case <-timer.C:
		d = g.settle(e, timedOut)
	case <-ctx.Done():
		g.settle(e, denied)
		return nil, ctx.Err()
	}
	switch d {
	case approved:
		return g.cfg.Bot.Handle(ctx, t, s)
	case timedOut:
		return nil, &bot.Failure{Message: TextTimedOut}
	}
	return nil, &bot.Failure{Message: TextDenied}
}

// enter records a waiting task, or returns the text that refuses it: too many
// wait, or a task with the same id already waits (it must not replace the entry
// the owner was shown, nor have its own end remove it).
func (g *Gate) enter(t bot.Task) (*entry, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.waiting[t.ID] != nil {
		return nil, TextDuplicate
	}
	if len(g.waiting) >= g.cfg.MaxPending {
		return nil, TextTooMany
	}
	same := 0
	for _, w := range g.waiting {
		if w.caller == t.Caller || w.owner == t.Owner {
			same++
		}
	}
	if same >= g.cfg.MaxPerCaller {
		return nil, TextTooMany
	}
	now := g.cfg.Now()
	e := &entry{id: t.ID, caller: t.Caller, owner: t.Owner, received: now, deadline: now.Add(g.cfg.Timeout), result: make(chan decision, 1)}
	n := min(len(t.Content), MaxPreview)
	e.preview, e.more = append([]byte(nil), t.Content[:n]...), len(t.Content) > n
	g.waiting[t.ID] = e
	return e, ""
}

// leave forgets a task and zeroes its preview.
func (g *Gate) leave(e *entry) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.waiting, e.id)
	clear(e.preview)
}

// settle takes the decision for e unless one was already taken, and returns the
// one that stands (so a timeout that lost the race to an approval runs the task).
func (g *Gate) settle(e *entry, d decision) decision {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e.decided {
		return <-e.result
	}
	e.decided = true
	return d
}

// Decide records the owner's answer for a waiting task: ErrNotPending when none
// with that id waits, was decided, or is past its deadline.
func (g *Gate) Decide(id [16]byte, approve bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.waiting[id]
	if e == nil || e.decided || !g.cfg.Now().Before(e.deadline) {
		return ErrNotPending
	}
	e.decided = true
	if approve {
		e.result <- approved
	} else {
		e.result <- denied
	}
	return nil
}

// Pending is what the owner sees of a waiting task.
type Pending struct {
	TaskID    string    `json:"task_id"`
	Caller    string    `json:"caller"`
	Owner     string    `json:"owner"`
	Received  time.Time `json:"received"`
	Expires   time.Time `json:"expires"`
	Preview   string    `json:"preview"`
	Truncated bool      `json:"truncated,omitempty"`
}

// List returns the tasks waiting for a decision, oldest first. Their text is
// untrusted: it is shown for the owner to read, never to act on.
func (g *Gate) List() []Pending {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Pending, 0, len(g.waiting))
	now := g.cfg.Now()
	for _, e := range g.waiting {
		if !e.decided && now.Before(e.deadline) { // past the deadline Decide refuses, so it is not offered
			out = append(out, Pending{TaskID: hex.EncodeToString(e.id[:]), Caller: printable(e.caller, maxIdentity), Owner: printable(e.owner, maxIdentity),
				Received: e.received, Expires: e.deadline, Preview: printable(string(e.preview), MaxPreview), Truncated: e.more})
		}
	}
	slices.SortFunc(out, func(a, b Pending) int {
		if c := a.Received.Compare(b.Received); c != 0 {
			return c
		}
		return strings.Compare(a.TaskID, b.TaskID)
	})
	return out
}

// printable cuts s to limit bytes at a character boundary and replaces what a
// terminal could act on (controls, escapes, bidirectional and other format
// characters, invalid bytes) with '.', and line breaks and tabs with a space.
func printable(s string, limit int) string {
	if len(s) > limit {
		for limit > 0 && !utf8.RuneStart(s[limit]) {
			limit--
		}
		s = s[:limit]
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r != utf8.RuneError && unicode.IsPrint(r) { // RuneError is what invalid bytes decode to
			return r
		}
		return '.'
	}, s)
}

// Methods are the local socket methods the owner's commands use: "approvals"
// (list), "approve" and "deny" (each with a task_id). Register them with
// Daemon.Handle. They carry no task content other than the preview.
func (g *Gate) Methods() map[string]localsock.Method {
	return map[string]localsock.Method{
		"approvals": func(context.Context, json.RawMessage) (any, error) {
			return struct {
				Pending   []Pending `json:"pending"`
				Untrusted bool      `json:"untrusted"` // the previews were written by another agent
			}{g.List(), true}, nil
		},
		"approve": g.decide(true),
		"deny":    g.decide(false),
	}
}

// DecideParams is the request of "approve" and "deny".
type DecideParams struct {
	TaskID string `json:"task_id"`
}

func (g *Gate) decide(approve bool) localsock.Method {
	word := "denied"
	if approve {
		word = "approved"
	}
	return func(_ context.Context, raw json.RawMessage) (any, error) {
		var p DecideParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &localsock.RPCError{Code: CodeBadParams}
		}
		b, err := hex.DecodeString(p.TaskID)
		if err != nil || len(b) != 16 || p.TaskID != strings.ToLower(p.TaskID) {
			return nil, &localsock.RPCError{Code: CodeBadParams}
		}
		if err := g.Decide([16]byte(b), approve); err != nil {
			return nil, &localsock.RPCError{Code: CodeNotFound}
		}
		return struct {
			TaskID   string `json:"task_id"`
			Decision string `json:"decision"`
		}{p.TaskID, word}, nil
	}
}
