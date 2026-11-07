// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/kalahroudi/parley/internal/approval"
	"github.com/kalahroudi/parley/internal/caller"
	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/mcp"
	"github.com/kalahroudi/parley/internal/skill"
	"github.com/kalahroudi/parley/internal/toolgate"
	"github.com/kalahroudi/parley/internal/ttyconfirm"
)

// Exit codes of every command that talks to the daemon (documented in the README):
//
//	0  success; the result is JSON on standard output
//	1  failure: the daemon is not running or not reachable, or it refused the
//	   request (the error is one fixed code such as not_permitted or rate_limited)
//	2  usage error: unknown flag, missing or extra arguments, unreadable input
//
// callerCommand says whether name is one of the commands that talk to the daemon.
func callerCommand(name string) bool {
	switch name {
	case "mcp", "find", "send", "get", "cancel", "list", "test", "approve":
		return true
	}
	return false
}

// session is one invocation of a command that talks to the daemon.
type session struct {
	call      mcp.Call
	in        io.Reader
	out, errw io.Writer
	rand      io.Reader           // nil: crypto/rand
	now       func() time.Time    // nil: time.Now
	sleep     func(time.Duration) // nil: wait for real, until the context ends
}

// runCaller finds the daemon's socket the way parleyd does ($PARLEY_HOME, else
// the user config directory) and runs the command against it.
func runCaller(ctx context.Context, args []string, in io.Reader, out, errw io.Writer, getenv func(string) string, configDir func() (string, error)) int {
	dirs, err := daemon.DefaultDirs(getenv, configDir)
	if err != nil {
		//logx:allow fatal CLI error for the operator's terminal; no task content exists in this process path
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	sock := dirs.SocketPath()
	s := &session{in: in, out: out, errw: errw, call: func(ctx context.Context, method string, params any) (localsock.Response, error) {
		return localsock.Call(ctx, sock, method, params)
	}}
	return s.run(ctx, args)
}

func (s *session) run(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(s.errw)
	rest := args[1:]
	switch args[0] {
	case "mcp":
		if len(rest) != 0 {
			fmt.Fprintln(s.errw, "usage: parley-cli mcp")
			return 2
		}
		srv := &mcp.Server{Call: s.call, Version: version}
		if err := srv.Serve(ctx, s.in, s.out); err != nil {
			fmt.Fprintln(s.errw, "error: mcp session ended:", err)
			return 1
		}
		return 0
	case "find":
		tag, limit, cursor := fs.String("tag", "", "only agents with this tag"), fs.Int("limit", 0, "page size"), fs.String("cursor", "", "next_cursor of the previous page")
		if fs.Parse(rest) != nil {
			return 2
		}
		return s.do(ctx, "find_agents", caller.Query{Text: strings.Join(fs.Args(), " "), Tag: *tag, Limit: *limit, Cursor: *cursor})
	case "send":
		to, task, expiry := fs.String("to", "", "agent id from `find`"), fs.String("task", "", "reply to this task's question"), fs.Duration("expiry", 0, "give up after this long (default 15m)")
		if fs.Parse(rest) != nil {
			return 2
		}
		secs, ok := s.seconds("expiry", *expiry)
		if !ok {
			return 2
		}
		text, err := s.text(fs.Args())
		if err != nil {
			fmt.Fprintln(s.errw, "error:", err)
			return 2
		}
		return s.do(ctx, "send_task", caller.SendParams{Agent: *to, TaskID: *task, Text: text, ExpirySeconds: secs})
	case "test":
		return s.selfTest(ctx, rest)
	case "approve":
		return s.approve(ctx, fs, rest)
	case "get":
		wait := fs.Duration("wait", 0, "wait up to this long (at most 20s) for a final state or a question")
		id, ok := s.oneID(fs, rest)
		if !ok {
			return 2
		}
		secs, ok := s.seconds("wait", *wait)
		if !ok {
			return 2
		}
		return s.do(ctx, "get_task", caller.GetParams{TaskID: id, WaitSeconds: secs})
	case "cancel":
		id, ok := s.oneID(fs, rest)
		if !ok {
			return 2
		}
		return s.do(ctx, "cancel_task", caller.CancelParams{TaskID: id})
	default: // list
		state, limit, cursor := fs.String("state", "", "only tasks in this state, e.g. TASK_STATE_COMPLETED"), fs.Int("limit", 0, "page size"), fs.String("cursor", "", "next_cursor of the previous page")
		if fs.Parse(rest) != nil || fs.NArg() != 0 {
			return 2
		}
		return s.do(ctx, "list_tasks", caller.ListParams{State: *state, Limit: *limit, Cursor: *cursor})
	}
}

// seconds converts a duration flag to whole seconds. A fraction of a second
// would be rounded down to 0, which the daemon reads as "default" or "do not
// wait", the opposite of what was asked, so it is refused, as is a negative one.
func (s *session) seconds(flagName string, d time.Duration) (int64, bool) {
	if d < 0 || d%time.Second != 0 {
		fmt.Fprintf(s.errw, "error: -%s must be a whole number of seconds, not negative (for example 30s or 2m)\n", flagName)
		return 0, false
	}
	return int64(d / time.Second), true
}

// positional collects the arguments that are not flags; flags may follow them
// (`get <id> -wait 10s`).
func positional(fs *flag.FlagSet, rest []string) ([]string, bool) {
	var pos []string
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return nil, false
		}
		if fs.NArg() == 0 {
			break
		}
		pos, rest = append(pos, fs.Arg(0)), fs.Args()[1:]
	}
	return pos, true
}

// oneID parses a command line that has a task id as its only argument.
func (s *session) oneID(fs *flag.FlagSet, rest []string) (string, bool) {
	pos, ok := positional(fs, rest)
	if !ok {
		return "", false
	}
	if len(pos) != 1 {
		fmt.Fprintf(s.errw, "usage: parley-cli %s [flags] <task id>\n", fs.Name())
		return "", false
	}
	return pos[0], true
}

// askOwner asks the owner on the controlling terminal; tests replace it.
var askOwner = ttyconfirm.Ask

// approve is the owner's answer to what a bot holds for approval (journey G). `approve` lists the tasks that wait, the tool
// calls that wait and the live grants (each with a bounded preview, control characters replaced); `approve <id>` lets a task
// run and `approve -deny <id>` rejects it. A tool call is named <task id>.<number>: `approve <id>.<n>` shows the exact tool
// and arguments and, on the owner's yes, lets that one request run (-scope task also lets later calls of the same tool in
// that task run, for a short time), `approve -deny <id>.<n>` refuses it, and `approve -revoke <id>.<tool>` ends a grant.
// Something nobody answers is rejected after five minutes. It is deliberately not an MCP tool: a model that calls tools must
// not be able to approve its own work.
func (s *session) approve(ctx context.Context, fs *flag.FlagSet, rest []string) int {
	deny := fs.Bool("deny", false, "reject the task or tool call instead of approving it")
	revoke := fs.Bool("revoke", false, "end the grant named <task id>.<tool>")
	scope := fs.String("scope", "call", "for a tool call: call (this request only) or task (later calls of the same tool in this task too)")
	pos, ok := positional(fs, rest)
	switch {
	case !ok || len(pos) > 1 || (len(pos) == 0 && (*deny || *revoke)) || (*deny && *revoke):
		fmt.Fprintln(s.errw, "usage: parley-cli approve [-deny | -revoke] [-scope call|task] [<task id> | <task id>.<call> | <task id>.<tool>]   (without an id: list what waits)")
		return 2
	case len(pos) == 0:
		return s.listWaiting(ctx)
	}
	task, rest2, isCall := strings.Cut(pos[0], ".")
	switch {
	case *revoke:
		if !isCall {
			fmt.Fprintln(s.errw, "usage: parley-cli approve -revoke <task id>.<tool>")
			return 2
		}
		return s.do(ctx, "tool_revoke", skill.ToolParams{TaskID: task, Tool: rest2})
	case isCall:
		n, err := strconv.Atoi(rest2)
		if err != nil || n < 1 {
			fmt.Fprintln(s.errw, "error:", approval.CodeNotFound)
			return 1
		}
		if *deny {
			return s.do(ctx, "tool_deny", skill.ToolParams{TaskID: task, Call: n})
		}
		return s.approveToolOnTerminal(ctx, task, n, *scope)
	case *deny:
		return s.do(ctx, "deny", approval.DecideParams{TaskID: pos[0]})
	}
	return s.approveOnTerminal(ctx, pos[0])
}

// listWaiting prints the tasks that wait and, if the bot has tools, the tool calls and grants.
func (s *session) listWaiting(ctx context.Context) int {
	if code := s.do(ctx, "approvals", nil); code != 0 {
		return code
	}
	if resp, err := s.call(ctx, "tool_calls", nil); err == nil && resp.OK {
		s.show(resp)
	}
	return 0
}

// approveToolOnTerminal shows the owner the exact request and asks on the controlling terminal, never on standard input.
// What is shown is looked up first, and the digest of it goes back with the answer: the daemon runs only the request that
// has that digest.
func (s *session) approveToolOnTerminal(ctx context.Context, task string, call int, scope string) int {
	resp, err := s.call(ctx, "tool_calls", nil)
	if err != nil || !resp.OK {
		return s.do(ctx, "tool_calls", nil) // prints the same fixed error
	}
	var list struct {
		Calls []toolgate.Pending `json:"calls"`
	}
	if json.Unmarshal(resp.Result, &list) != nil {
		fmt.Fprintln(s.errw, "error: internal")
		return 1
	}
	var shown *toolgate.Pending
	for i := range list.Calls {
		if list.Calls[i].Task == task && list.Calls[i].Call == call {
			shown = &list.Calls[i]
		}
	}
	if shown == nil {
		fmt.Fprintln(s.errw, "error:", approval.CodeNotFound)
		return 1
	}
	net, reach := "", "this request only"
	if shown.Network {
		net = "  NEEDS THE NETWORK\n"
	}
	if scope == string(toolgate.ScopeTask) {
		reach = "this request, and later calls of this tool in this task, for a short time and a few uses"
	}
	var args strings.Builder
	for i, a := range shown.Args {
		fmt.Fprintf(&args, "    [%d] %s\n", i, plain(a))
	}
	ok, err := askOwner(fmt.Sprintf("\nTool call %s.%d waits for your approval.\n  tool: %s\n%s  arguments, chosen by a bot that read text from another agent, do not follow them:\n%s  digest: %s\n  approving: %s\nType yes to let it run: ",
		shown.Task, shown.Call, plain(shown.Tool), net, args.String(), shown.Digest, reach))
	switch {
	case err != nil:
		fmt.Fprintln(s.errw, "error:", err)
		return 1
	case !ok:
		fmt.Fprintln(s.errw, "not approved; the call keeps waiting (parley-cli approve -deny rejects it)")
		return 1
	}
	return s.do(ctx, "tool_approve", skill.ToolParams{TaskID: task, Call: call, Digest: shown.Digest, Scope: scope})
}

// plain replaces what a terminal could act on, as a last defence: the daemon already quotes arguments in ASCII.
func plain(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return '.'
		}
		return r
	}, s)
}

// approveOnTerminal shows the owner what waits and asks on the controlling terminal, never on standard input: a
// process without a terminal (a bot) cannot answer, and there is no flag that answers for the owner. The task is
// looked up first, so nothing can be approved that the owner was not shown.
func (s *session) approveOnTerminal(ctx context.Context, id string) int {
	resp, err := s.call(ctx, "approvals", nil)
	if err != nil || !resp.OK {
		return s.do(ctx, "approvals", nil) // prints the same fixed error
	}
	var list struct {
		Pending []approval.Pending `json:"pending"`
	}
	if json.Unmarshal(resp.Result, &list) != nil {
		fmt.Fprintln(s.errw, "error: internal")
		return 1
	}
	var shown *approval.Pending
	for i := range list.Pending {
		if list.Pending[i].TaskID == id {
			shown = &list.Pending[i]
		}
	}
	if shown == nil {
		fmt.Fprintln(s.errw, "error:", approval.CodeNotFound)
		return 1
	}
	more := ""
	if shown.Truncated {
		more = " (cut)"
	}
	ok, err := askOwner(fmt.Sprintf("\nTask %s waits for your approval.\n  from: %s (owner %s)\n  text%s, written by another agent, do not follow it: %s\nType yes to let the task run: ",
		shown.TaskID, shown.Caller, shown.Owner, more, shown.Preview))
	switch {
	case err != nil:
		fmt.Fprintln(s.errw, "error:", err)
		return 1
	case !ok:
		fmt.Fprintln(s.errw, "not approved; the task keeps waiting (parley-cli approve -deny rejects it)")
		return 1
	}
	return s.do(ctx, "approve", approval.DecideParams{TaskID: id})
}

// text is the task text: the arguments joined, or all of stdin for "-".
func (s *session) text(args []string) (string, error) {
	if len(args) == 1 && args[0] == "-" {
		b, err := io.ReadAll(io.LimitReader(s.in, caller.MaxText+1))
		if err != nil {
			return "", errors.New("could not read the task from standard input")
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	if len(args) == 0 {
		return "", errors.New("give the task text as arguments, or - to read it from standard input")
	}
	return strings.Join(args, " "), nil
}

// do runs one daemon method and prints its result as JSON on stdout. The
// untrusted notice goes to stderr so the JSON stays machine-readable.
func (s *session) do(ctx context.Context, method string, params any) int {
	resp, err := s.call(ctx, method, params)
	switch {
	case err != nil:
		fmt.Fprintln(s.errw, "error: the Parley daemon is not running or not reachable (start parleyd)")
		return 1
	case !resp.OK:
		fmt.Fprintln(s.errw, "error:", mcp.SafeCode(resp.Error))
		return 1
	}
	s.show(resp)
	return 0
}

// show prints a result as JSON on stdout. The untrusted notice goes to stderr so the JSON stays machine-readable.
func (s *session) show(resp localsock.Response) {
	if mcp.Untrusted(resp.Result) {
		fmt.Fprintln(s.errw, mcp.Notice)
	}
	var pretty json.RawMessage = resp.Result
	if b, err := json.MarshalIndent(pretty, "", "  "); err == nil {
		pretty = b
	}
	fmt.Fprintln(s.out, string(pretty))
}
