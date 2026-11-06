// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package skill is the rule that keeps tool-using skills behind the owner's
// approval (journey G). A skill is what a published bot can do: tool-less (it
// only reads the task and answers) or tool-using (it may run programs, read
// files or call services on the owner's machine, so a task from another agent
// is a request to act there).
//
// The rules, enforced here and nowhere left to the configuration:
//
//   - A tool-using skill is always held for the owner's approval: Gate refuses
//     any other mode, and an unset mode counts as "none". There is no way to
//     publish a tool-using skill that runs unattended.
//   - Tool-using skills are unsupported on Windows until a sandbox exists:
//     Check fails there, whatever the approval mode.
//   - A tool-using skill carries a fixed label ("tool-using") for its card and
//     for the owner's listing, so callers and owners can tell it from a
//     tool-less one. The label is self-declared text on a plaintext card and is
//     not something the gateway or a caller can verify.
//
// What this does not do: it is no sandbox. An approved tool-using bot runs with
// the rights of the owner's OS user; approval is the owner's judgment of one
// task, and the prompt may still be hostile. docs/sandbox and the README state
// what each OS enforces.
package skill

import (
	"errors"

	"github.com/kalahroudi/parley/internal/approval"
	"github.com/kalahroudi/parley/internal/bot"
)

// Fixed texts. Labels are literals so that no skill name or task text can reach them.
const (
	LabelToolLess  = "tool-less"
	LabelToolUsing = "tool-using: runs only after the owner approves each task; not sandboxed"
)

var (
	// ErrNeedsApproval means a tool-using skill was configured with an approval mode other than "owner".
	ErrNeedsApproval = errors.New("skill: a tool-using skill must use the owner approval mode")
	// ErrUnsupportedOS means a tool-using skill was configured on an OS without a sandbox.
	ErrUnsupportedOS = errors.New("skill: tool-using skills are unsupported on this operating system")
	// ErrConfig means the skill is incomplete or its approval mode is unknown.
	ErrConfig = errors.New("skill: incomplete configuration")
)

// Skill is the part of a bot's configuration that decides who must approve a task.
type Skill struct {
	// ToolUsing is true when the bot may act on the machine (run programs, touch files, call services).
	ToolUsing bool
	// Approval is the mode from the bot's configuration; empty means "none".
	Approval approval.Mode
}

// Check reports whether the skill may run on the operating system named by goos (runtime.GOOS).
func Check(s Skill, goos string) error {
	switch s.Approval {
	case "", approval.None, approval.Owner:
	default:
		return ErrConfig
	}
	if !s.ToolUsing {
		return nil
	}
	if goos == "windows" {
		return ErrUnsupportedOS
	}
	if s.Approval != approval.Owner {
		return ErrNeedsApproval
	}
	return nil
}

// Label is the text for the card and the owner's listing.
func Label(s Skill) string {
	if s.ToolUsing {
		return LabelToolUsing
	}
	return LabelToolLess
}

// Gate wraps b for the skill: a tool-using skill gets the owner approval gate,
// a tool-less one the mode it asked for. cfg supplies the gate's limits; its Bot and Mode are ignored.
func Gate(b bot.Bot, s Skill, goos string, cfg approval.Config) (*approval.Gate, error) {
	if b == nil {
		return nil, ErrConfig
	}
	if err := Check(s, goos); err != nil {
		return nil, err
	}
	cfg.Bot, cfg.Mode = b, s.Approval
	return approval.New(cfg)
}
