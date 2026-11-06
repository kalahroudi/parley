// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package toolgate decides whether a tool a bot asks for may run (journey G). A
// skill is tool-less unless its configuration declares tools in a Manifest; a
// bot that wants one sends a Request, and the Broker runs it only after the
// owner approved that exact request. Nothing runs by default.
//
// What this guarantees, exactly:
//
//   - Deny by default. A request for a tool that is not in the manifest, with
//     more or longer arguments than the manifest allows, with an argument that is
//     not plain printable text, or beyond the task's call limit, is refused with
//     the fixed outcome "refused" and nothing runs.
//   - What the owner is shown is what runs. A call is captured by value when it
//     is requested; the owner sees the tool, every argument quoted in ASCII
//     (arguments are limited to printable characters, so the quoting is lossless),
//     whether it needs the network, and a digest over the task id, call number,
//     tool, network flag and arguments. The answer must carry that digest, so an
//     approval for one request cannot be applied to another.
//   - A call is approved by call number: the bot sees no call number and cannot
//     choose one. A decision is taken once, under a lock; a second answer, an
//     answer after the timeout, after the task ended or after a denial is refused.
//     The arguments are copied when the call arrives and again when it runs, so
//     neither the bot's buffers nor the runner can change what was approved.
//   - A grant (scope "task") lets later calls to the same tool, within the
//     manifest's limits, run without asking again, for a short time and a few uses,
//     only for that task; it ends with the task, on expiry, on use up and on
//     Revoke, which also cancels a call running under it. A tool that needs the
//     network is never granted: each of its calls is approved on its own.
//   - Everything is bounded: calls per task (MaxCalls), arguments, run time,
//     output size, calls waiting for approval (MaxPending), grants.
//   - What comes back to the bot is data, never instructions: the output is cut
//     to the tool's limit, characters a terminal or a reader could be misled by
//     (controls, escapes, bidirectional and format characters, invalid bytes) are
//     replaced, and it is wrapped in lines that carry a random boundary the tool
//     could not have known, with a label saying it is untrusted.
//   - Every request, refusal, answer, run and revocation is reported to Audit
//     with ids and a state code only, never an argument or output.
//
// What it does not do: it does not run anything (a Runner does, see
// internal/toolrun) and it cannot make an approved tool safe: approval is the
// owner's judgment of one request, and what the tool then does with the rights it
// is given is the Runner's containment.
package toolgate

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits, as single literals so that the mutation gate can cover them (TestConstantsArePinned pins them).
const (
	MaxTools        = 32
	maxNameLen      = 32
	DefaultMaxArgs  = 8
	HardMaxArgs     = 32
	DefaultArgBytes = 1024
	HardArgBytes    = 8192
	DefaultOutput   = 65536
	HardOutput      = 1048576
	MaxCalls        = 32 // calls per task, granted or not
	DefaultPending  = 16
	MaxGrantUses    = 16
)

// Durations, kept apart so that they are literals too.
const (
	DefaultTimeout  = time.Duration(30e9)  // a tool's run time
	HardTimeout     = time.Duration(600e9) // the longest a manifest may ask for
	DefaultApproval = time.Duration(300e9) // 5 minutes to answer, as for tasks
	MaxGrantTTL     = time.Duration(900e9) // 15 minutes
)

// Outcomes, the only things the bot learns about a call.
type Outcome string

const (
	OutcomeOK      Outcome = "ok"      // the tool ran and exited 0
	OutcomeExit    Outcome = "exit"    // the tool ran and exited with a nonzero status
	OutcomeDenied  Outcome = "denied"  // the owner said no, or did not answer in time
	OutcomeRefused Outcome = "refused" // the request broke the manifest or a limit
	OutcomeFailed  Outcome = "failed"  // the tool could not be run
	OutcomeTimeout Outcome = "timeout" // the tool ran out of time and was killed
)

// States reported to Audit (all are in logx.States).
const (
	StateRequested = "TOOL_REQUESTED"
	StateApproved  = "TOOL_APPROVED"
	StateDenied    = "TOOL_DENIED"
	StateRefused   = "TOOL_REFUSED"
	StateNoAnswer  = "TOOL_NO_ANSWER"
	StateGranted   = "TOOL_GRANTED"
	StateUsedGrant = "TOOL_GRANT_USED"
	StateRevoked   = "TOOL_REVOKED"
	StateRan       = "TOOL_RAN"
	StateFailed    = "TOOL_FAILED"
	StateTimeout   = "TOOL_TIMEOUT"
	StateCanceled  = "TOOL_CANCELED"
)

// Errors of the owner's side.
var (
	ErrConfig     = errors.New("toolgate: incomplete or invalid configuration")
	ErrNotPending = errors.New("toolgate: no such call is waiting")
	ErrDigest     = errors.New("toolgate: the answer is for a different request")
	ErrScope      = errors.New("toolgate: this scope is not allowed for this call")
	ErrNoGrant    = errors.New("toolgate: no such grant")
)

// Scope is how far an approval reaches.
type Scope string

const (
	ScopeCall Scope = "call" // this request only
	ScopeTask Scope = "task" // later calls to the same tool in this task, within the manifest's limits
)

// Tool is one entry of a manifest. Zero limits take the defaults.
type Tool struct {
	Name     string
	Network  bool // the tool needs the network: declared here, approved per call, denied to the process otherwise
	MaxArgs  int
	ArgBytes int
	Timeout  time.Duration
	Output   int
}

// Manifest is the set of tools a skill declares. The zero value declares none.
type Manifest struct{ tools map[string]Tool }

// NewManifest validates and normalises a list of tools.
func NewManifest(tools []Tool) (Manifest, error) {
	if len(tools) > MaxTools {
		return Manifest{}, ErrConfig
	}
	m := Manifest{tools: make(map[string]Tool, len(tools))}
	for _, t := range tools {
		if !validName(t.Name) || m.tools[t.Name].Name != "" {
			return Manifest{}, ErrConfig
		}
		var ok [4]bool
		t.MaxArgs, ok[0] = limit(t.MaxArgs, DefaultMaxArgs, HardMaxArgs)
		t.ArgBytes, ok[1] = limit(t.ArgBytes, DefaultArgBytes, HardArgBytes)
		t.Output, ok[2] = limit(t.Output, DefaultOutput, HardOutput)
		d, ok3 := limit(int(t.Timeout), int(DefaultTimeout), int(HardTimeout))
		t.Timeout, ok[3] = time.Duration(d), ok3
		if slices.Contains(ok[:], false) {
			return Manifest{}, ErrConfig
		}
		m.tools[t.Name] = t
	}
	return m, nil
}

// limit applies the default to zero and refuses a negative value or one above hard.
func limit(v, def, hard int) (int, bool) {
	if v < 0 || v > hard {
		return 0, false
	}
	if v == 0 {
		return def, true
	}
	return v, true
}

func validName(s string) bool {
	if s == "" || len(s) > maxNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Lookup returns the tool named name.
func (m Manifest) Lookup(name string) (Tool, bool) {
	t, ok := m.tools[name]
	return t, ok
}

// Len is the number of declared tools.
func (m Manifest) Len() int { return len(m.tools) }

// Request is what a bot asks for.
type Request struct {
	Tool string
	Args []string
}

// check reports whether req fits tool t.
func check(t Tool, args []string) bool {
	if len(args) > t.MaxArgs {
		return false
	}
	for _, a := range args {
		if len(a) > t.ArgBytes || !plain(a) {
			return false
		}
	}
	return true
}

// plain admits valid UTF-8 made only of printable characters and the space: no control, format (bidirectional
// marks, zero-width joiners), private-use or unassigned characters, so that an argument is what it looks like.
func plain(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r != ' ' && !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// Digest binds an answer to one request: task id, call number, tool, network flag and arguments, each length-prefixed.
func Digest(task [16]byte, call int, tool string, network bool, args []string) string {
	h := sha256.New()
	put := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	put("parley-toolcall/1")
	put(string(task[:]))
	put(strconv.Itoa(call))
	put(tool)
	put(strconv.FormatBool(network))
	put(strconv.Itoa(len(args)))
	for _, a := range args {
		put(a)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Output is what a Runner returns.
type Output struct {
	Data      []byte
	Truncated bool // more output than the tool's limit
	Exit      int
}

// Runner runs an approved request. args are exactly the approved arguments.
type Runner interface {
	Run(ctx context.Context, t Tool, args []string) (Output, error)
}

// Event is one audit record. It holds ids and a state only.
type Event struct {
	Task  [16]byte
	Call  int
	Tool  string
	State string
}

// Config sets a Broker.
type Config struct {
	Manifest Manifest
	Runner   Runner
	// Approval is how long a call waits for the owner (default 5 minutes).
	Approval time.Duration
	// MaxPending bounds the calls waiting for an answer, over all tasks.
	MaxPending int
	Now        func() time.Time
	Rand       io.Reader
	Audit      func(Event) // must not block for long; nil discards
}

// Broker applies the manifest and the owner's answers. It is safe for concurrent use.
type Broker struct {
	cfg Config

	mu      sync.Mutex
	tasks   map[[16]byte]*taskState
	waiting map[callKey]*pending
}

type callKey struct {
	task [16]byte
	call int
}

type taskState struct {
	calls  int
	grants map[string]*grant
}

type grant struct {
	expires time.Time
	uses    int
	ctx     context.Context
	revoke  context.CancelFunc
}

type pending struct {
	key      callKey
	tool     Tool
	args     []string // a private copy
	digest   string
	received time.Time
	deadline time.Time
	decided  bool
	result   chan answer // buffered: the deciding side never blocks
}

type answer struct {
	approve bool
	scope   Scope
}

// New builds a Broker. A manifest with no tools, or no runner, is a configuration error.
func New(cfg Config) (*Broker, error) {
	if cfg.Manifest.Len() == 0 || cfg.Runner == nil {
		return nil, ErrConfig
	}
	if cfg.Approval <= 0 {
		cfg.Approval = DefaultApproval
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = DefaultPending
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	cfg.Rand = &lockedReader{r: cfg.Rand}
	if cfg.Audit == nil {
		cfg.Audit = func(Event) {}
	}
	return &Broker{cfg: cfg, tasks: map[[16]byte]*taskState{}, waiting: map[callKey]*pending{}}, nil
}

// lockedReader lets calls running at once share one random source.
type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (l *lockedReader) Read(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(p)
}

// Reply is what the bot receives for one call. Data is framed and neutralised (see Frame) and is empty unless the
// tool ran.
type Reply struct {
	Outcome   Outcome
	Exit      int
	Truncated bool
	Data      []byte
}

// Call asks for a tool on behalf of a task. It returns an error only when ctx ends (the caller's cancel, the task's
// expiry, shutdown); every other result is an Outcome. onWait is called once, if the call has to wait for the owner.
func (b *Broker) Call(ctx context.Context, task [16]byte, taskExpiry time.Time, req Request, onWait func()) (Reply, error) {
	t, ok := b.cfg.Manifest.Lookup(req.Tool)
	st, n, refused := b.begin(task, t, ok && check(t, req.Args))
	if refused {
		b.audit(task, n, req.Tool, StateRefused)
		return Reply{Outcome: OutcomeRefused}, nil
	}
	args := slices.Clone(req.Args)
	gctx, g := b.useGrant(st, task, t)
	if g == nil {
		var ok bool
		if gctx, ok = b.approve(ctx, task, n, t, args, taskExpiry, onWait); !ok {
			if err := ctx.Err(); err != nil {
				b.audit(task, n, t.Name, StateCanceled)
				return Reply{}, err
			}
			return Reply{Outcome: OutcomeDenied}, nil
		}
	}
	return b.run(ctx, gctx, task, n, t, args)
}

// begin counts the call against the task and refuses one that is not allowed. n is the call number.
func (b *Broker) begin(task [16]byte, t Tool, fits bool) (*taskState, int, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.tasks[task]
	if st == nil {
		st = &taskState{grants: map[string]*grant{}}
		b.tasks[task] = st
	}
	if st.calls >= MaxCalls || !fits {
		return st, st.calls, true
	}
	st.calls++
	return st, st.calls, false
}

// useGrant returns the live grant for the tool and spends a use of it.
func (b *Broker) useGrant(st *taskState, task [16]byte, t Tool) (context.Context, *grant) {
	b.mu.Lock()
	defer b.mu.Unlock()
	g := st.grants[t.Name]
	if g == nil {
		return nil, nil
	}
	if g.uses <= 0 || !b.cfg.Now().Before(g.expires) {
		g.revoke()
		delete(st.grants, t.Name)
		return nil, nil
	}
	g.uses--
	b.audit(task, st.calls, t.Name, StateUsedGrant)
	return g.ctx, g
}

// approve queues the call for the owner and waits for the answer. The returned context ends when a grant made by
// the answer is revoked (it is nil for a one-call approval).
func (b *Broker) approve(ctx context.Context, task [16]byte, n int, t Tool, args []string, taskExpiry time.Time, onWait func()) (context.Context, bool) {
	e, ok := b.enter(task, n, t, args)
	if !ok {
		b.audit(task, n, t.Name, StateRefused)
		return nil, false
	}
	defer b.leave(e)
	timer := time.NewTimer(b.cfg.Approval)
	defer timer.Stop()
	b.audit(task, n, t.Name, StateRequested)
	if onWait != nil {
		onWait()
	}
	var a answer
	select {
	case a = <-e.result:
	case <-timer.C:
		a = b.settle(e, answer{})
		if !a.approve {
			b.audit(task, n, t.Name, StateNoAnswer)
			return nil, false
		}
	case <-ctx.Done():
		b.settle(e, answer{}) // an answer recorded in the same instant is dropped: the task is over
		return nil, false
	}
	if !a.approve {
		b.audit(task, n, t.Name, StateDenied)
		return nil, false
	}
	b.audit(task, n, t.Name, StateApproved)
	if a.scope != ScopeTask {
		return nil, true
	}
	return b.grant(task, t, taskExpiry), true
}

// enter records the call as waiting, or refuses it when too many wait.
func (b *Broker) enter(task [16]byte, n int, t Tool, args []string) (*pending, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.waiting) >= b.cfg.MaxPending {
		return nil, false
	}
	now := b.cfg.Now()
	e := &pending{key: callKey{task, n}, tool: t, args: args, digest: Digest(task, n, t.Name, t.Network, args),
		received: now, deadline: now.Add(b.cfg.Approval), result: make(chan answer, 1)}
	b.waiting[e.key] = e
	return e, true
}

func (b *Broker) leave(e *pending) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.waiting, e.key)
}

// settle takes the decision for e unless one was already taken, and returns the one that stands.
func (b *Broker) settle(e *pending, d answer) answer {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e.decided {
		return <-e.result
	}
	e.decided = true
	return d
}

// grant records a task-scope grant, replacing a spent one, and returns its context.
func (b *Broker) grant(task [16]byte, t Tool, taskExpiry time.Time) context.Context {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.tasks[task]
	if st == nil { // the task ended while the owner decided
		return nil
	}
	expires := b.cfg.Now().Add(MaxGrantTTL)
	if !taskExpiry.IsZero() && taskExpiry.Before(expires) {
		expires = taskExpiry
	}
	if old := st.grants[t.Name]; old != nil {
		old.revoke()
	}
	ctx, cancel := context.WithCancel(context.Background())
	st.grants[t.Name] = &grant{expires: expires, uses: MaxGrantUses, ctx: ctx, revoke: cancel}
	b.audit(task, st.calls, t.Name, StateGranted)
	return ctx
}

// run executes the approved request. gctx, if not nil, cancels the run when the grant it ran under is revoked.
func (b *Broker) run(ctx, gctx context.Context, task [16]byte, n int, t Tool, args []string) (Reply, error) {
	rctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	if gctx != nil {
		defer context.AfterFunc(gctx, cancel)()
	}
	out, err := b.cfg.Runner.Run(rctx, t, slices.Clone(args)) // the runner gets its own copy: the approved one stays as shown
	if ctx.Err() != nil {
		b.audit(task, n, t.Name, StateCanceled)
		return Reply{}, ctx.Err()
	}
	if gctx != nil && gctx.Err() != nil { // the grant was revoked while the tool ran: its result is not delivered
		b.audit(task, n, t.Name, StateRevoked)
		return Reply{Outcome: OutcomeDenied}, nil
	}
	if errors.Is(rctx.Err(), context.DeadlineExceeded) {
		b.audit(task, n, t.Name, StateTimeout)
		return Reply{Outcome: OutcomeTimeout}, nil
	}
	if err != nil {
		b.audit(task, n, t.Name, StateFailed)
		return Reply{Outcome: OutcomeFailed}, nil
	}
	b.audit(task, n, t.Name, StateRan)
	data, rerr := Frame(t.Name, out.Data, t.Output, b.cfg.Rand)
	if rerr != nil {
		return Reply{Outcome: OutcomeFailed}, nil
	}
	r := Reply{Outcome: OutcomeOK, Exit: out.Exit, Truncated: out.Truncated, Data: data}
	if out.Exit != 0 {
		r.Outcome = OutcomeExit
	}
	return r, nil
}

func (b *Broker) audit(task [16]byte, call int, tool, state string) {
	b.cfg.Audit(Event{Task: task, Call: call, Tool: tool, State: state})
}

// End forgets a finished task: its grants stop and any call running under one is canceled.
func (b *Broker) End(task [16]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if st := b.tasks[task]; st != nil {
		for _, g := range st.grants {
			g.revoke()
		}
		delete(b.tasks, task)
	}
}

// Decide records the owner's answer to the call task/call. An approval must carry the digest the owner was shown.
func (b *Broker) Decide(task [16]byte, call int, digest string, approve bool, scope Scope) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.waiting[callKey{task, call}]
	if e == nil || e.decided || !b.cfg.Now().Before(e.deadline) {
		return ErrNotPending
	}
	if approve && e.digest != digest { // a denial can run nothing, so it needs no proof of what was shown
		return ErrDigest
	}
	if scope == "" {
		scope = ScopeCall
	}
	if scope != ScopeCall && (scope != ScopeTask || e.tool.Network) {
		return ErrScope
	}
	e.decided = true
	e.result <- answer{approve: approve, scope: scope}
	return nil
}

// Revoke ends the grant of tool for task and cancels a call running under it.
func (b *Broker) Revoke(task [16]byte, tool string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	st := b.tasks[task]
	if st == nil || st.grants[tool] == nil {
		return ErrNoGrant
	}
	st.grants[tool].revoke()
	delete(st.grants, tool)
	b.audit(task, st.calls, tool, StateRevoked)
	return nil
}

// Pending is what the owner sees of a waiting call. Args are quoted in ASCII, one string each.
type Pending struct {
	Task     string    `json:"task_id"`
	Call     int       `json:"call"`
	Tool     string    `json:"tool"`
	Args     []string  `json:"args"`
	Network  bool      `json:"network"`
	Digest   string    `json:"digest"`
	Received time.Time `json:"received"`
	Expires  time.Time `json:"expires"`
}

// Grant is what the owner sees of a live grant.
type Grant struct {
	Task    string    `json:"task_id"`
	Tool    string    `json:"tool"`
	Uses    int       `json:"uses_left"`
	Expires time.Time `json:"expires"`
}

// Pending lists the calls waiting for an answer, oldest first.
func (b *Broker) Pending() []Pending {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.cfg.Now()
	out := make([]Pending, 0, len(b.waiting))
	for _, e := range b.waiting {
		if !e.decided && now.Before(e.deadline) { // past the deadline Decide refuses, so it is not offered
			q := make([]string, len(e.args))
			for i, a := range e.args {
				q[i] = strconv.QuoteToASCII(a)
			}
			out = append(out, Pending{Task: hex.EncodeToString(e.key.task[:]), Call: e.key.call, Tool: e.tool.Name, Args: q,
				Network: e.tool.Network, Digest: e.digest, Received: e.received, Expires: e.deadline})
		}
	}
	slices.SortFunc(out, func(x, y Pending) int {
		return cmp.Or(x.Received.Compare(y.Received), strings.Compare(x.Task, y.Task), cmp.Compare(x.Call, y.Call))
	})
	return out
}

// Grants lists the live grants, ordered by task then tool.
func (b *Broker) Grants() []Grant {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.cfg.Now()
	out := []Grant{}
	for id, st := range b.tasks {
		for tool, g := range st.grants {
			if g.uses > 0 && now.Before(g.expires) {
				out = append(out, Grant{Task: hex.EncodeToString(id[:]), Tool: tool, Uses: g.uses, Expires: g.expires})
			}
		}
	}
	slices.SortFunc(out, func(x, y Grant) int {
		return cmp.Or(strings.Compare(x.Task, y.Task), strings.Compare(x.Tool, y.Tool))
	})
	return out
}
