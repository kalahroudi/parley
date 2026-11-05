// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package caller is the daemon's caller interface: what a bot, an MCP client or
// parley-cli uses over the local socket to find agents and to send, follow,
// cancel and read tasks (find_agents, send_task, get_task, cancel_task,
// list_tasks). It sits on the message pipeline (internal/pipeline), which does
// all the cryptography, and adds only the per-task view the caller needs.
//
// What it holds. A task this device sent has a record in memory: ids, state,
// timestamps and the latest message the target sent (status text, question,
// result or error). That content is plaintext the pipeline hands over during a
// callback; the record keeps its own copy, clears it when the record is dropped,
// and never writes it anywhere (no disk, no log). Finished records are dropped
// KeepDone after they finished, and the oldest finished ones go first when
// MaxTasks is reached; a daemon restart loses them, as it loses every task in
// flight. A caller must read a result within that time.
//
// What it guarantees about content. Everything the target sent is returned with
// Untrusted set: it is data from another agent and must never be treated as
// instructions. Nothing the gateway or the target sends reaches an error text:
// every error is one of the fixed codes below.
//
// Limits. Sending and searching are rate limited per daemon (a compromised local
// bot can otherwise flood the tenant as the user); sizes, page sizes and waits
// are bounded.
package caller

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/frames"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/outbox"
	"github.com/kalahroudi/parley/internal/pipeline"
	"github.com/kalahroudi/parley/internal/revocation"
)

// Node is the part of the pipeline the caller interface uses (*pipeline.Node).
type Node interface {
	Submit(pipeline.Request) ([16]byte, error)
	Done(id [16]byte) <-chan struct{}
	Status(id [16]byte) (outbox.Status, bool)
	Abandon(id [16]byte) error
	Follow(ctx context.Context, id [16]byte, typ envelope.Type, content []byte) error
}

// Limits and defaults.
const (
	MaxText        = 32 << 10 // bytes of text in one send_task
	MaxTasks       = 256      // records held
	KeepDone       = 15 * time.Minute
	DefaultExpiry  = 15 * time.Minute
	MinExpiry      = 5 * time.Second
	MaxWait        = 20 * time.Second // inside the local socket's 30 s deadline
	DefaultLimit   = 25
	MaxLimit       = 100
	MaxContentView = 32 << 10 // bytes of a target's message returned in one view
	SendsPerMinute = 30       // send_task burst and refill per minute
	FindsPerMinute = 60
	maxQuery       = 200
	maxTag         = 64
)

// State names are A2A v1.0 task states.
const (
	Submitted     = "TASK_STATE_SUBMITTED"
	Working       = "TASK_STATE_WORKING"
	InputRequired = "TASK_STATE_INPUT_REQUIRED"
	Completed     = "TASK_STATE_COMPLETED"
	Failed        = "TASK_STATE_FAILED"
	Canceled      = "TASK_STATE_CANCELED"
	Rejected      = "TASK_STATE_REJECTED"
)

// Error codes sent to the client. They are fixed identifiers (localsock.RPCError).
const (
	CodeBadParams  = "bad_params"
	CodeNotReady   = "not_ready"
	CodeBusy       = "busy"
	CodeRateLimit  = "rate_limited"
	CodeNotFound   = "not_found"
	CodeNotAllowed = "not_permitted"
	CodeTooLarge   = "too_large"
	CodeNoKey      = "no_key_yet"
	CodeWrongState = "wrong_state"
	CodeDirectory  = "directory_unavailable"
	CodeSending    = "sending"
	CodeInternal   = "internal"
)

// Reasons a task ended without a result: fixed text, never the peer's.
const (
	ReasonOffline    = "recipient_offline"
	ReasonGone       = "recipient_not_found"
	ReasonNotAllowed = "not_permitted"
	ReasonRefused    = "recipient_refused"
	ReasonNotReady   = "not_ready"
	ReasonExpired    = "expired"
	ReasonSendFailed = "send_failed"
	ReasonBusy       = "busy"
)

// Content kinds: what the target's latest message is.
const (
	KindStatus   = "status"
	KindQuestion = "question"
	KindResult   = "result"
	KindError    = "error"
)

// Config wires a Service.
type Config struct {
	// Node returns the pipeline; it fails (pipeline.ErrNotReady, daemon.ErrNotEnrolled)
	// until the device is enrolled.
	Node func() (Node, error)
	// Find searches the tenant directory (Directory.Find).
	Find func(ctx context.Context, q Query) (*Page, error)
	Now  func() time.Time
}

// Service is the caller interface. It is safe for concurrent use.
type Service struct {
	cfg    Config
	sends  *bucket
	finds  *bucket
	closed chan struct{}

	mu    sync.Mutex
	seq   uint64
	tasks map[[16]byte]*task
}

// New builds a Service.
func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{
		cfg: cfg, tasks: map[[16]byte]*task{}, closed: make(chan struct{}),
		sends: newBucket(SendsPerMinute, cfg.Now), finds: newBucket(FindsPerMinute, cfg.Now),
	}
}

// Close wipes every record's content and wakes waiters. Call it when the daemon stops.
func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	for id, t := range s.tasks {
		t.wipe()
		delete(s.tasks, id)
	}
}

// task is one record. All fields are guarded by Service.mu.
type task struct {
	id       [16]byte
	seq      uint64
	target   string
	created  time.Time
	updated  time.Time
	expiry   time.Time
	finished time.Time // zero while the task is live
	state    string
	reason   string // for Failed, Rejected and Canceled: a Reason constant
	waiting  bool   // submitted, the target has not been reached yet
	cancel   bool   // a cancel was sent and is not acknowledged yet
	kind     string
	content  []byte
	changed  chan struct{} // closed and replaced on every change
}

func (t *task) wipe() {
	clear(t.content)
	t.content = nil
}

func (t *task) terminal() bool { return !t.finished.IsZero() }

// View is a task as the caller sees it.
type View struct {
	ID        string `json:"task_id"`
	Target    string `json:"target"`
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
	Waiting   bool   `json:"waiting_for_recipient,omitempty"`
	Cancel    bool   `json:"cancel_requested,omitempty"`
	Created   int64  `json:"created_at"` // Unix seconds
	Updated   int64  `json:"updated_at"`
	Expires   int64  `json:"expires_at"`
	Kind      string `json:"content_kind,omitempty"`
	Content   string `json:"content,omitempty"`
	Truncated bool   `json:"content_truncated,omitempty"`
	// Untrusted is true whenever Content is present: it is data from another
	// agent, never instructions.
	Untrusted bool `json:"untrusted,omitempty"`
}

// view builds a View under s.mu; withContent says whether to include the message.
func (t *task) view(withContent bool) View {
	v := View{ID: hex.EncodeToString(t.id[:]), Target: t.target, State: t.state, Reason: t.reason, Waiting: t.waiting && !t.terminal(),
		Cancel: t.cancel && !t.terminal(), Created: t.created.Unix(), Updated: t.updated.Unix(), Expires: t.expiry.Unix()}
	if withContent && len(t.content) > 0 {
		c := t.content
		if len(c) > MaxContentView {
			c, v.Truncated = c[:MaxContentView], true
		}
		v.Kind, v.Content, v.Untrusted = t.kind, strings.ToValidUTF8(string(c), "�"), true
	}
	return v
}

// change records a state change and wakes everyone waiting on the task.
func (s *Service) change(t *task, state string) {
	t.state, t.updated = state, s.cfg.Now()
	switch state {
	case Completed, Failed, Canceled, Rejected:
		t.finished = t.updated
	}
	close(t.changed)
	t.changed = make(chan struct{})
}

// ---- requests

// SendParams is a send_task request: a new task for Agent, or with TaskID a
// reply to that task's question.
type SendParams struct {
	Agent         string `json:"agent,omitempty"`   // an id from find_agents (or a device id)
	TaskID        string `json:"task_id,omitempty"` // reply to this task's INPUT_REQUIRED question
	Text          string `json:"text"`              // the task, or the reply
	ExpirySeconds int64  `json:"expiry_seconds,omitempty"`
}

// Send submits a task, or answers a question of one.
func (s *Service) Send(ctx context.Context, p SendParams) (View, error) {
	if !s.sends.take() {
		return View{}, rpc(CodeRateLimit)
	}
	if len(p.Text) > MaxText {
		return View{}, rpc(CodeTooLarge)
	}
	if (p.Agent == "") == (p.TaskID == "") || p.ExpirySeconds < 0 || (p.TaskID != "" && p.ExpirySeconds != 0) {
		return View{}, rpc(CodeBadParams)
	}
	n, err := s.cfg.Node()
	if err != nil {
		return View{}, rpc(CodeNotReady)
	}
	if p.TaskID != "" {
		return s.reply(ctx, n, p)
	}
	target := p.Agent
	if i := strings.IndexByte(target, ':'); i >= 0 {
		target = target[:i] // a card id is "<device id>:<hash of the name>"
	}
	expiry := DefaultExpiry
	if p.ExpirySeconds > 0 {
		if p.ExpirySeconds > int64(outbox.MaxExpiry/time.Second) {
			return View{}, rpc(CodeBadParams)
		}
		expiry = time.Duration(p.ExpirySeconds) * time.Second
	}
	if !frames.ValidID(target) || expiry < MinExpiry {
		return View{}, rpc(CodeBadParams)
	}
	now := s.cfg.Now()
	// The lock is held through Submit so that no update for the new task can
	// arrive before its record exists (Submit does not call back into us).
	s.mu.Lock()
	if !s.makeRoom(now) {
		s.mu.Unlock()
		return View{}, rpc(CodeBusy)
	}
	id, err := n.Submit(pipeline.Request{Target: target, Content: []byte(p.Text), Expiry: now.Add(expiry)})
	if err != nil {
		s.mu.Unlock()
		return View{}, toRPC(err)
	}
	s.seq++
	t := &task{id: id, seq: s.seq, target: target, created: now, updated: now, expiry: now.Add(expiry), state: Submitted, waiting: true, changed: make(chan struct{})}
	s.tasks[id] = t
	v := t.view(false)
	s.mu.Unlock()
	go s.watch(n, t)
	return v, nil
}

// watch follows the outbox until the task has been sent or has failed before it was.
func (s *Service) watch(n Node, t *task) {
	select {
	case <-n.Done(t.id):
	case <-s.closed:
		return
	}
	s.settle(n, t)
}

// settle records how the outbox finished with a task.
func (s *Service) settle(n Node, t *task) {
	st, _ := n.Status(t.id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.terminal() || s.tasks[t.id] != t {
		return
	}
	t.waiting = false
	switch st.State {
	case outbox.Sent:
		s.change(t, t.state) // wake waiters: the task is with the target now
	case outbox.Canceled:
		s.change(t, Canceled)
	default: // Failed, or an outbox that forgot the task
		state, reason := failure(st.Err)
		t.reason = reason
		s.change(t, state)
	}
}

func (s *Service) reply(ctx context.Context, n Node, p SendParams) (View, error) {
	id, ok := parseID(p.TaskID)
	if !ok {
		return View{}, rpc(CodeBadParams)
	}
	s.mu.Lock()
	t := s.tasks[id]
	s.mu.Unlock()
	if t == nil {
		return View{}, rpc(CodeNotFound)
	}
	if err := n.Follow(ctx, id, envelope.TypeReply, []byte(p.Text)); err != nil {
		return View{}, toRPC(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !t.terminal() {
		t.kind = ""
		t.wipe()
		s.change(t, Working)
	}
	return t.view(false), nil
}

// Update applies a message about a task this device sent (the pipeline's
// OnUpdate). The content is copied: the pipeline's buffer is cleared after the call.
func (s *Service) Update(u pipeline.Update) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tasks[u.TaskID]
	if t == nil || t.terminal() {
		return
	}
	t.waiting = false
	set := func(kind string) {
		t.wipe()
		t.kind, t.content = kind, append([]byte(nil), u.Content...)
	}
	switch {
	case u.Expired && t.cancel:
		t.reason = ReasonExpired
		s.change(t, Canceled)
	case u.Expired:
		t.reason = ReasonExpired
		s.change(t, Failed)
	case u.Type == envelope.TypeStatus:
		set(KindStatus)
		s.change(t, Working)
	case u.Type == envelope.TypeInputRequired:
		set(KindQuestion)
		s.change(t, InputRequired)
	case u.Type == envelope.TypeResult:
		set(KindResult)
		s.change(t, Completed)
	case u.Type == envelope.TypeError:
		set(KindError)
		s.change(t, Failed)
	case u.Type == envelope.TypeCancel:
		t.wipe()
		s.change(t, Canceled)
	}
}

// GetParams is a get_task request. WaitSeconds waits (up to MaxWait) for the
// task to finish or ask a question; it returns early on either.
type GetParams struct {
	TaskID      string `json:"task_id"`
	WaitSeconds int64  `json:"wait_seconds,omitempty"`
}

// Get returns a task's state and the target's latest message.
func (s *Service) Get(ctx context.Context, p GetParams) (View, error) {
	id, ok := parseID(p.TaskID)
	if !ok || p.WaitSeconds < 0 {
		return View{}, rpc(CodeBadParams)
	}
	wait := min(time.Duration(p.WaitSeconds)*time.Second, MaxWait)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		s.mu.Lock()
		t := s.tasks[id]
		if t == nil {
			s.mu.Unlock()
			return View{}, rpc(CodeNotFound)
		}
		if t.terminal() || t.state == InputRequired || wait == 0 {
			v := t.view(true)
			s.mu.Unlock()
			return v, nil
		}
		ch := t.changed
		s.mu.Unlock()
		select {
		case <-ch:
		case <-timer.C:
			wait = 0 // one last look, then return what is there
		case <-ctx.Done():
			return View{}, rpc(CodeInternal)
		case <-s.closed:
			return View{}, rpc(CodeNotReady)
		}
	}
}

// CancelParams is a cancel_task request.
type CancelParams struct {
	TaskID string `json:"task_id"`
}

// Cancel stops a task. One still waiting for its recipient is canceled at once
// and the recipient never hears of it. A sent one gets a signed CANCEL, and ends
// when the target acknowledges (or after the pipeline's CancelWait).
func (s *Service) Cancel(ctx context.Context, p CancelParams) (View, error) {
	id, ok := parseID(p.TaskID)
	if !ok {
		return View{}, rpc(CodeBadParams)
	}
	s.mu.Lock()
	t := s.tasks[id]
	var waiting, done bool
	if t != nil {
		waiting, done = t.waiting, t.terminal()
	}
	s.mu.Unlock()
	if t == nil {
		return View{}, rpc(CodeNotFound)
	}
	if done {
		return View{}, rpc(CodeWrongState)
	}
	n, err := s.cfg.Node()
	if err != nil {
		return View{}, rpc(CodeNotReady)
	}
	if waiting {
		switch err := n.Abandon(id); {
		case err == nil:
			s.settle(n, t)
			s.mu.Lock()
			defer s.mu.Unlock()
			return t.view(false), nil
		case errors.Is(err, outbox.ErrSending):
			return View{}, rpc(CodeSending)
		case errors.Is(err, outbox.ErrAlreadySent):
			// Sent a moment ago: it is a sent task now.
		default:
			return View{}, toRPC(err)
		}
	}
	if err := n.Follow(ctx, id, envelope.TypeCancel, nil); err != nil {
		return View{}, toRPC(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t.cancel = true
	return t.view(false), nil
}

// ListParams is a list_tasks request: newest first, one page at a time.
type ListParams struct {
	State  string `json:"state,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"` // from a previous page's next_cursor
}

// ListResult is a page of tasks (without their content: ask for one with get_task).
type ListResult struct {
	Tasks      []View `json:"tasks"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// List returns this device's tasks, newest first.
func (s *Service) List(_ context.Context, p ListParams) (ListResult, error) {
	limit := p.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	var before uint64 = 1<<64 - 1
	if p.Cursor != "" {
		b, err := hex.DecodeString(p.Cursor)
		if err != nil || len(b) != 8 {
			return ListResult{}, rpc(CodeBadParams)
		}
		before = 0
		for _, c := range b {
			before = before<<8 | uint64(c)
		}
	}
	if limit < 1 || limit > MaxLimit || (p.State != "" && !validState(p.State)) {
		return ListResult{}, rpc(CodeBadParams)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var match []*task
	for _, t := range s.tasks {
		if t.seq < before && (p.State == "" || t.state == p.State) {
			match = append(match, t)
		}
	}
	sortNewestFirst(match)
	res := ListResult{Tasks: []View{}}
	for i, t := range match {
		if i == limit {
			res.NextCursor = cursorOf(match[i-1].seq)
			break
		}
		res.Tasks = append(res.Tasks, t.view(false))
	}
	return res, nil
}

// ---- helpers

func validState(s string) bool {
	switch s {
	case Submitted, Working, InputRequired, Completed, Failed, Canceled, Rejected:
		return true
	}
	return false
}

func parseID(s string) ([16]byte, bool) {
	var id [16]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) || s != strings.ToLower(s) {
		return id, false
	}
	copy(id[:], b)
	return id, true
}

// makeRoom drops expired finished records, then the oldest finished ones, until
// there is room for one more; false when every record is a live task. Call with s.mu held.
func (s *Service) makeRoom(now time.Time) bool {
	for id, t := range s.tasks {
		if t.terminal() && now.Sub(t.finished) > KeepDone {
			t.wipe()
			delete(s.tasks, id)
		}
	}
	for len(s.tasks) >= MaxTasks {
		var oldest *task
		for _, t := range s.tasks {
			if t.terminal() && (oldest == nil || t.finished.Before(oldest.finished)) {
				oldest = t
			}
		}
		if oldest == nil {
			return false
		}
		oldest.wipe()
		delete(s.tasks, oldest.id)
	}
	return true
}

// rpc is an error with a fixed code for the client.
func rpc(code string) error { return &localsock.RPCError{Code: code} }

// toRPC maps an error from the pipeline or the outbox to a fixed code. The text
// of the error is dropped: it may be derived from what a peer or the gateway said.
func toRPC(err error) error {
	switch {
	case errors.Is(err, outbox.ErrInvalid), errors.Is(err, outbox.ErrExpired):
		return rpc(CodeBadParams)
	case errors.Is(err, pipeline.ErrBusy), errors.Is(err, outbox.ErrFull), errors.Is(err, outbox.ErrTargetFull):
		return rpc(CodeBusy)
	case errors.Is(err, pipeline.ErrUnknown), errors.Is(err, outbox.ErrUnknown):
		return rpc(CodeNotFound)
	case errors.Is(err, pipeline.ErrState):
		return rpc(CodeWrongState)
	case errors.Is(err, pipeline.ErrNoKey):
		return rpc(CodeNoKey)
	case errors.Is(err, pipeline.ErrNotReady), errors.Is(err, revocation.ErrNoList), errors.Is(err, revocation.ErrStale), errors.Is(err, revocation.ErrRevoked):
		return rpc(CodeNotReady)
	case errors.Is(err, pipeline.ErrNotPermitted), errors.Is(err, pipeline.ErrPeer):
		return rpc(CodeNotAllowed)
	}
	return rpc(CodeInternal)
}

// failure maps why a task was never sent to its final state and a fixed reason.
func failure(err error) (state, reason string) {
	switch {
	case errors.Is(err, outbox.ErrRecipientOffline):
		return Failed, ReasonOffline
	case errors.Is(err, outbox.ErrGone):
		return Failed, ReasonGone
	case errors.Is(err, pipeline.ErrNotPermitted), errors.Is(err, pipeline.ErrPeer):
		return Rejected, ReasonNotAllowed
	case errors.Is(err, pipeline.ErrRefused), errors.Is(err, pipeline.ErrPrekey):
		return Rejected, ReasonRefused
	case errors.Is(err, pipeline.ErrBusy), errors.Is(err, outbox.ErrFull), errors.Is(err, outbox.ErrTargetFull):
		return Rejected, ReasonBusy
	case errors.Is(err, pipeline.ErrNotReady), errors.Is(err, revocation.ErrNoList), errors.Is(err, revocation.ErrStale), errors.Is(err, revocation.ErrRevoked):
		return Failed, ReasonNotReady
	case errors.Is(err, outbox.ErrExpired):
		return Failed, ReasonExpired
	}
	return Failed, ReasonSendFailed
}

// Methods are the local socket methods, ready for Daemon.Handle.
func (s *Service) Methods() map[string]localsock.Method {
	return map[string]localsock.Method{
		"find_agents": decode(s.FindAgents),
		"send_task":   decode(s.Send),
		"get_task":    decode(s.Get),
		"cancel_task": decode(s.Cancel),
		"list_tasks":  decode(s.List),
	}
}

// decode turns a typed handler into a socket method that refuses unknown fields and trailing data.
func decode[P, R any](f func(context.Context, P) (R, error)) localsock.Method {
	return func(ctx context.Context, raw json.RawMessage) (any, error) {
		var p P
		if len(raw) > 0 {
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&p); err != nil || dec.More() {
				return nil, rpc(CodeBadParams)
			}
		}
		return f(ctx, p)
	}
}

func cursorOf(seq uint64) string {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i], seq = byte(seq), seq>>8
	}
	return hex.EncodeToString(b[:])
}

// validText reports whether s is usable as a query: valid UTF-8 without control characters.
func validText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
