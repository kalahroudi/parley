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
//   - A skill is tool-less unless it says it is tool-using or declares tools
//     (Skill.Tools, the manifest); declaring tools makes it tool-using.
//   - A tool-using skill is always held for the owner's approval: Gate refuses
//     any other mode, and an unset mode counts as "none". There is no way to
//     publish a tool-using skill that runs unattended.
//   - Every call of a declared tool is approved by the owner on its own, bound
//     to the exact tool and arguments shown (Bridge, ToolMethods; the rules are
//     in internal/toolgate, the confinement of the process in internal/toolrun).
//   - Tool-using skills are unsupported on Windows until a sandbox exists:
//     Check fails there, whatever the approval mode.
//   - A tool-using skill carries a fixed label ("tool-using") for its card and
//     for the owner's listing, so callers and owners can tell it from a
//     tool-less one. The label is self-declared text on a plaintext card and is
//     not something the gateway or a caller can verify.
//
// What this does not do: it does not confine the bot's own process. A bot that
// acts by itself (ToolUsing without a manifest, or a bot that simply runs
// something) has the rights of the owner's OS user; approval is the owner's
// judgment of one task, and the prompt may still be hostile. Only the tools
// declared in the manifest run in a sandbox. docs/sandbox and the README state
// what each OS enforces.
package skill

import (
	"errors"

	"github.com/kalahroudi/parley/internal/approval"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/toolgate"
)

// Fixed texts. Labels are literals so that no skill name or task text can reach them.
const (
	LabelToolLess  = "tool-less"
	LabelToolUsing = "tool-using: runs only after the owner approves each task; each tool call needs the owner's approval too"
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
	// ToolUsing is true when the bot may act on the machine (run programs, touch files, call services) by itself.
	ToolUsing bool
	// Tools is the manifest: the tools the bot may ask the daemon to run (each call needs the owner's approval, see
	// internal/toolgate). A skill with tools is tool-using whatever ToolUsing says.
	Tools []toolgate.Tool
	// Approval is the mode from the bot's configuration; empty means "none".
	Approval approval.Mode
}

// Uses reports whether the skill is tool-using: it says so, or it declares tools.
func (s Skill) Uses() bool { return s.ToolUsing || len(s.Tools) > 0 }

// Check reports whether the skill may run on the operating system named by goos (runtime.GOOS).
func Check(s Skill, goos string) error {
	switch s.Approval {
	case "", approval.None, approval.Owner:
	default:
		return ErrConfig
	}
	if _, err := toolgate.NewManifest(s.Tools); err != nil {
		return ErrConfig
	}
	if !s.Uses() {
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
	if s.Uses() {
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
