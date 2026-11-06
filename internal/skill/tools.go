// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package skill

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/approval"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/toolgate"
)

// Error codes the owner's tool commands receive, besides approval.CodeBadParams and approval.CodeNotFound.
const (
	CodeDigest = "digest_mismatch" // the answer is for a different request than the one waiting
	CodeScope  = "bad_scope"
)

type bridge struct{ b *toolgate.Broker }

// Bridge lets the CLI adapter ask b for the tools a bot requests.
func Bridge(b *toolgate.Broker) adapter.Tools { return bridge{b} }

func (br bridge) Call(ctx context.Context, t bot.Task, tool string, args []string, onWait func()) (adapter.ToolReply, error) {
	r, err := br.b.Call(ctx, t.ID, t.Expiry, toolgate.Request{Tool: tool, Args: args}, onWait)
	return adapter.ToolReply{Outcome: string(r.Outcome), Exit: r.Exit, Truncated: r.Truncated, Content: r.Data}, err
}

func (br bridge) End(task [16]byte) { br.b.End(task) }

// ToolParams is the request of "tool_approve", "tool_deny" and "tool_revoke". Digest is the one "tool_calls" showed;
// Scope is "call" (default) or "task"; Tool is for "tool_revoke".
type ToolParams struct {
	TaskID string `json:"task_id"`
	Call   int    `json:"call,omitempty"`
	Digest string `json:"digest,omitempty"`
	Scope  string `json:"scope,omitempty"`
	Tool   string `json:"tool,omitempty"`
}

// ToolMethods are the local socket methods of the owner's tool commands: "tool_calls" (list what waits and the live
// grants), "tool_approve", "tool_deny" and "tool_revoke". "tool_approve", "tool_deny" and "tool_revoke" belong with the
// sensitive methods of the daemon: a bot must not reach them.
func ToolMethods(b *toolgate.Broker) map[string]localsock.Method {
	return map[string]localsock.Method{
		"tool_calls": func(context.Context, json.RawMessage) (any, error) {
			return struct {
				Calls     []toolgate.Pending `json:"calls"`
				Grants    []toolgate.Grant   `json:"grants"`
				Untrusted bool               `json:"untrusted"` // the arguments were chosen by a bot that read another agent's text
			}{b.Pending(), b.Grants(), true}, nil
		},
		"tool_approve": decide(b, true),
		"tool_deny":    decide(b, false),
		"tool_revoke": func(_ context.Context, raw json.RawMessage) (any, error) {
			p, id, ok := parse(raw)
			if !ok || !validTool(p.Tool) {
				return nil, &localsock.RPCError{Code: approval.CodeBadParams}
			}
			if err := b.Revoke(id, p.Tool); err != nil {
				return nil, &localsock.RPCError{Code: approval.CodeNotFound}
			}
			return struct {
				TaskID string `json:"task_id"`
				Tool   string `json:"tool"`
				State  string `json:"state"`
			}{p.TaskID, p.Tool, "revoked"}, nil
		},
	}
}

func validTool(s string) bool {
	_, err := toolgate.NewManifest([]toolgate.Tool{{Name: s}})
	return err == nil
}

// parse reads the parameters and the task id they carry.
func parse(raw json.RawMessage) (ToolParams, [16]byte, bool) {
	var p ToolParams
	if json.Unmarshal(raw, &p) != nil {
		return p, [16]byte{}, false
	}
	b, err := hex.DecodeString(p.TaskID)
	if err != nil || len(b) != 16 || p.TaskID != strings.ToLower(p.TaskID) {
		return p, [16]byte{}, false
	}
	return p, [16]byte(b), true
}

func decide(b *toolgate.Broker, approve bool) localsock.Method {
	word := "denied"
	if approve {
		word = "approved"
	}
	return func(_ context.Context, raw json.RawMessage) (any, error) {
		p, id, ok := parse(raw)
		if !ok || p.Call < 1 {
			return nil, &localsock.RPCError{Code: approval.CodeBadParams}
		}
		err := b.Decide(id, p.Call, p.Digest, approve, toolgate.Scope(p.Scope))
		switch {
		case errors.Is(err, toolgate.ErrDigest):
			return nil, &localsock.RPCError{Code: CodeDigest}
		case errors.Is(err, toolgate.ErrScope):
			return nil, &localsock.RPCError{Code: CodeScope}
		case err != nil:
			return nil, &localsock.RPCError{Code: approval.CodeNotFound}
		}
		return struct {
			TaskID   string `json:"task_id"`
			Call     int    `json:"call"`
			Decision string `json:"decision"`
		}{p.TaskID, p.Call, word}, nil
	}
}
