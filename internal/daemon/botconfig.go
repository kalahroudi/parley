// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"time"
	"unicode"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/approval"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/skill"
	"github.com/kalahroudi/parley/internal/toolgate"
	"github.com/kalahroudi/parley/internal/toolrun"
)

// The bot a device runs is configured here, and everything that makes a tool-using skill safe is applied here, from the
// configuration, with no way around it:
//
//   - the allowlist is required and denies by default: only callers whose root-signed binding names a listed owner reach the
//     bot (names are compared with ASCII case folding only);
//   - a skill that declares tools (or says it is tool-using) must use the owner approval mode, and is refused on Windows
//     (skill.Check); an unset mode means "owner" for such a skill, "none" for a tool-less one;
//   - each declared tool runs in the sandbox of internal/toolrun, after the owner approved that exact call
//     (internal/toolgate); where no sandbox exists the daemon does not start;
//   - approvals, denials, refusals and tool calls are logged with ids and states only.
//
// Any problem stops startup. There is no degraded mode.

// Limits on the configuration.
const (
	maxAllowOwners = 64
	maxOwnerLen    = 128
)

// BotConfig configures the bot. The CLI and ACP adapters are configurable here (a program the daemon runs per task); the
// API adapter needs a bearer token, which does not belong in a public configuration file.
type BotConfig struct {
	Adapter string   `json:"adapter"` // "cli" or "acp"
	Command string   `json:"command"` // absolute path
	Args    []string `json:"args,omitempty"`
	Dir     string   `json:"dir,omitempty"` // the bot's working directory (absolute); required for "acp", whose session is rooted in it
	Env     []string `json:"env,omitempty"` // the whole environment of the bot ("NAME=value")
	// AllowOwners are the owners (binding identities) whose callers may use the bot. Required.
	AllowOwners []string `json:"allow_owners"`
	// ToolUsing says the bot acts on the machine by itself. Declaring Tools makes it tool-using too.
	ToolUsing bool `json:"tool_using,omitempty"`
	// Approval is "none" or "owner"; unset means "owner" for a tool-using skill and "none" for a tool-less one.
	Approval string `json:"approval,omitempty"`
	// Tools is the manifest: the tools the bot may ask the daemon to run, each call only after the owner approves it.
	Tools []ToolConfig `json:"tools,omitempty"`
}

// ToolConfig declares one tool: how it runs and what it may be asked.
type ToolConfig struct {
	Name     string   `json:"name"`
	Command  string   `json:"command"` // absolute path, run directly
	Args     []string `json:"args,omitempty"`
	Dir      string   `json:"dir"` // the jail: absolute, must exist; the only place the tool can write
	Env      []string `json:"env,omitempty"`
	Network  bool     `json:"network,omitempty"` // the tool needs the network; each call is approved on its own
	MaxArgs  int      `json:"max_args,omitempty"`
	ArgBytes int      `json:"max_arg_bytes,omitempty"`
	Timeout  string   `json:"timeout,omitempty"` // Go duration
	Output   int      `json:"max_output,omitempty"`
}

func (b *BotConfig) validate() error {
	if b.Adapter != "cli" && b.Adapter != "acp" {
		return errors.New(`bot.adapter must be "cli" or "acp"`)
	}
	if b.Adapter == "acp" && (b.Dir == "" || len(b.Tools) > 0) {
		return errors.New(`bot.adapter "acp" needs bot.dir and takes no bot.tools (an ACP agent has no way to ask the daemon for one)`)
	}
	if !filepath.IsAbs(b.Command) || (b.Dir != "" && !filepath.IsAbs(b.Dir)) {
		return errors.New("bot.command and bot.dir must be absolute paths")
	}
	if n := len(b.AllowOwners); n == 0 || n > maxAllowOwners {
		return fmt.Errorf("bot.allow_owners needs 1 to %d owners", maxAllowOwners)
	}
	for _, o := range b.AllowOwners {
		if !plainOwner(o) {
			return errors.New("bot.allow_owners holds an empty, long or unprintable name")
		}
	}
	switch b.Approval {
	case "", string(approval.None), string(approval.Owner):
	default:
		return errors.New(`bot.approval must be "none" or "owner"`)
	}
	if _, err := b.toolList(); err != nil {
		return err
	}
	// The remaining checks (the approval mode against the skill, the operating system, the sandbox) run in New.
	return nil
}

func plainOwner(s string) bool {
	if s == "" || len(s) > maxOwnerLen {
		return false
	}
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) || r == ' ' {
			return false
		}
	}
	return true
}

// toolList converts the declared tools to the broker's manifest entries, checking each.
func (b *BotConfig) toolList() ([]toolgate.Tool, error) {
	out := make([]toolgate.Tool, 0, len(b.Tools))
	for _, t := range b.Tools {
		if !filepath.IsAbs(t.Command) || !filepath.IsAbs(t.Dir) {
			return nil, errors.New("bot.tools: command and dir must be absolute paths")
		}
		var timeout time.Duration
		if t.Timeout != "" {
			d, err := time.ParseDuration(t.Timeout)
			if err != nil || d <= 0 {
				return nil, errors.New("bot.tools: timeout must be a positive duration")
			}
			timeout = d
		}
		out = append(out, toolgate.Tool{Name: t.Name, Network: t.Network, MaxArgs: t.MaxArgs, ArgBytes: t.ArgBytes, Timeout: timeout, Output: t.Output})
	}
	if _, err := toolgate.NewManifest(out); err != nil {
		return nil, errors.New("bot.tools: a name is not 1-32 characters of A-Z a-z 0-9 - _, is repeated, or a limit is out of range")
	}
	return out, nil
}

// skill is the skill the configuration describes.
func (b *BotConfig) skill() (skill.Skill, error) {
	tools, err := b.toolList()
	if err != nil {
		return skill.Skill{}, err
	}
	s := skill.Skill{ToolUsing: b.ToolUsing, Tools: tools, Approval: approval.Mode(b.Approval)}
	if s.Approval == "" && s.Uses() {
		s.Approval = approval.Owner
	}
	return s, nil
}

// asciiEqual compares two names with ASCII case folding only: Unicode folding would let a different identity (for
// instance one with a Kelvin sign) pass for a listed one.
func asciiEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func (d *Daemon) allowListed(owner string) bool {
	for _, o := range d.cfg.Bot.AllowOwners {
		if asciiEqual(o, owner) {
			return true
		}
	}
	return false
}

// initBot builds the configured bot: the CLI or ACP adapter, its tools if any, the approval gate and the host, and registers the
// owner's commands. It does nothing without a bot in the configuration.
func (d *Daemon) initBot() error {
	bc := d.cfg.Bot
	if bc == nil {
		return nil
	}
	if d.deps.Allow != nil || d.deps.OnInbound != nil {
		return fmt.Errorf("%w: a bot is configured and another was supplied", ErrConfig)
	}
	sk, err := bc.skill()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}
	goos := d.deps.OS
	if goos == "" {
		goos = runtime.GOOS
	}
	if err := skill.Check(sk, goos); err != nil {
		return err
	}
	var tools adapter.Tools
	if len(sk.Tools) > 0 {
		b, err := d.newBroker(sk.Tools)
		if err != nil {
			return err
		}
		tools = skill.Bridge(b)
		for name, m := range skill.ToolMethods(b) {
			d.srv.Methods[name] = m
		}
	}
	var program bot.Bot
	if bc.Adapter == "acp" {
		b, err := d.newACPBroker()
		if err != nil {
			return err
		}
		for name, m := range skill.ToolMethods(b) {
			d.srv.Methods[name] = m
		}
		program, err = adapter.NewACP(adapter.ACPConfig{Command: bc.Command, Args: bc.Args, Dir: bc.Dir, Env: bc.Env, Gate: skill.Bridge(b)})
		if err != nil {
			return fmt.Errorf("%w: bot command, directory or environment", ErrConfig)
		}
	} else {
		program, err = adapter.NewCLI(adapter.CLIConfig{Command: bc.Command, Args: bc.Args, Dir: bc.Dir, Env: bc.Env, Tools: tools})
	}
	if err != nil {
		return fmt.Errorf("%w: bot command, directory or environment", ErrConfig)
	}
	// Gate fails only for a skill Check refused (checked above), without a bot, or with an unknown mode (Check again).
	gate, _ := skill.Gate(program, sk, goos, approval.Config{Now: d.deps.Now, Audit: d.auditApproval})
	for name, m := range gate.Methods() {
		d.srv.Methods[name] = m
	}
	host, _ := bot.NewHost(bot.Config{Bot: gate, Responder: nodeResponder{d}, Now: d.deps.Now}) // fails only without a bot or a responder
	d.host = host
	d.deps.OnInbound = host.Inbound
	d.deps.Allow = d.allowListed
	return nil
}

// newBroker builds the tool broker with the runner of internal/toolrun (or the one the tests supply).
func (d *Daemon) newBroker(list []toolgate.Tool) (*toolgate.Broker, error) {
	m, _ := toolgate.NewManifest(list) // skill.Check has accepted this list
	var err error
	runner := d.deps.ToolRunner
	if runner == nil {
		if runner, err = newToolRunner(d.cfg.Bot, d.dirs); err != nil {
			return nil, err
		}
	}
	return toolgate.New(toolgate.Config{Manifest: m, Runner: runner, Now: d.deps.Now, Audit: d.auditTool})
}

// newACPBroker builds the broker through which an ACP agent's permission requests and file operations reach the owner. Its
// tools only ask: the runner does nothing, the adapter does what the owner allowed (and only inside the agent's directory).
func (d *Daemon) newACPBroker() (*toolgate.Broker, error) {
	m, _ := toolgate.NewManifest([]toolgate.Tool{{Name: adapter.ToolACPPermission}, {Name: adapter.ToolACPRead}, {Name: adapter.ToolACPWrite}}) // valid names
	return toolgate.New(toolgate.Config{Manifest: m, Runner: askOnly{}, Now: d.deps.Now, Audit: d.auditTool})
}

// askOnly is the runner of the ACP broker: an allowed request needs nothing run.
type askOnly struct{}

func (askOnly) Run(context.Context, toolgate.Tool, []string) (toolgate.Output, error) {
	return toolgate.Output{}, nil
}

// auditApproval logs one step of a task's approval: the task id and a state, nothing else.
func (d *Daemon) auditApproval(id [16]byte, state string) {
	d.deps.Log.Info("approval", logx.ID("task", hex.EncodeToString(id[:])), logx.State("state", state))
}

// auditTool logs one step of a tool call: ids and a state, never an argument or output.
func (d *Daemon) auditTool(e toolgate.Event) {
	d.deps.Log.Info("tool call", logx.ID("task", hex.EncodeToString(e.Task[:])), logx.ID("tool", e.Tool),
		logx.Size("call", int64(e.Call)), logx.State("state", e.State))
}

// newToolRunner is the sandboxed runner of internal/toolrun for the declared tools. It fails with toolrun.ErrNoSandbox where
// the system has no sandbox to confine a tool with, and with toolrun.ErrConfig for a tool directory that does not exist.
func newToolRunner(bc *BotConfig, dirs Dirs) (toolgate.Runner, error) {
	specs := make(map[string]toolrun.Spec, len(bc.Tools))
	for _, t := range bc.Tools {
		specs[t.Name] = toolrun.Spec{Command: t.Command, Args: t.Args, Dir: t.Dir, Env: t.Env}
	}
	r, err := toolrun.New(toolrun.Config{Specs: specs, Hide: []string{dirs.Config, dirs.State}})
	return r, err // on error r is nil and the caller stops: it never uses the runner
}
