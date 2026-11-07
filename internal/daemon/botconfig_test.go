// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kalahroudi/parley/internal/pipeline"
	"github.com/kalahroudi/parley/internal/skill"
	"github.com/kalahroudi/parley/internal/toolgate"
	"github.com/kalahroudi/parley/internal/toolrun"
)

type nopRunner struct{}

func (nopRunner) Run(context.Context, toolgate.Tool, []string) (toolgate.Output, error) {
	return toolgate.Output{}, nil
}

func abs(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// goodBot is a valid tool-less bot; the callers edit it.
func goodBot(t *testing.T) *BotConfig {
	return &BotConfig{Adapter: "cli", Command: abs(t, "bot"), AllowOwners: []string{"a@x.test"}}
}

func withTool(t *testing.T, b *BotConfig) *BotConfig {
	b.Tools = []ToolConfig{{Name: "grep", Command: abs(t, "grep"), Dir: t.TempDir(), Timeout: "5s"}}
	return b
}

func TestBotConfigIsValidatedAtParseTime(t *testing.T) {
	good := func(b *BotConfig) error {
		c := newEnv(t).cfg
		c.Bot = b
		_, err := ParseConfig(mustJSON(c))
		return err
	}
	if err := good(goodBot(t)); err != nil {
		t.Fatalf("a valid bot: %v", err)
	}
	if err := good(withTool(t, goodBot(t))); err != nil {
		t.Fatalf("a valid tool-using bot: %v", err)
	}
	owners := make([]string, maxAllowOwners+1)
	for i := range owners {
		owners[i] = "o@x.test"
	}
	longOwner := strings.Repeat("a", maxOwnerLen+1)
	for name, edit := range map[string]func(*BotConfig){
		"no adapter":         func(b *BotConfig) { b.Adapter = "" },
		"api adapter":        func(b *BotConfig) { b.Adapter = "api" },
		"relative command":   func(b *BotConfig) { b.Command = "bot" },
		"relative dir":       func(b *BotConfig) { b.Dir = "d" },
		"no owners":          func(b *BotConfig) { b.AllowOwners = nil },
		"too many owners":    func(b *BotConfig) { b.AllowOwners = owners },
		"empty owner":        func(b *BotConfig) { b.AllowOwners = []string{""} },
		"long owner":         func(b *BotConfig) { b.AllowOwners = []string{longOwner} },
		"owner with space":   func(b *BotConfig) { b.AllowOwners = []string{"a b"} },
		"owner with control": func(b *BotConfig) { b.AllowOwners = []string{"a\x1b"} },
		"owner not ascii":    func(b *BotConfig) { b.AllowOwners = []string{"é@x.test"} },
		"unknown approval":   func(b *BotConfig) { b.Approval = "auto" },
		"tool name":          func(b *BotConfig) { withTool(t, b).Tools[0].Name = "a b" },
		"tool repeated":      func(b *BotConfig) { withTool(t, b).Tools = append(b.Tools, b.Tools[0]) },
		"tool relative cmd":  func(b *BotConfig) { withTool(t, b).Tools[0].Command = "grep" },
		"tool relative dir":  func(b *BotConfig) { withTool(t, b).Tools[0].Dir = "jail" },
		"tool no dir":        func(b *BotConfig) { withTool(t, b).Tools[0].Dir = "" },
		"tool bad timeout":   func(b *BotConfig) { withTool(t, b).Tools[0].Timeout = "soon" },
		"tool zero timeout":  func(b *BotConfig) { withTool(t, b).Tools[0].Timeout = "-1s" },
		"tool limit":         func(b *BotConfig) { withTool(t, b).Tools[0].MaxArgs = toolgate.HardMaxArgs + 1 },
	} {
		b := goodBot(t)
		edit(b)
		if err := good(b); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Exactly the limits are fine.
	b := goodBot(t)
	b.AllowOwners = owners[:maxAllowOwners]
	b.AllowOwners[0] = strings.Repeat("a", maxOwnerLen)
	if err := good(b); err != nil {
		t.Errorf("the limits: %v", err)
	}
}

func TestOwnerNamesAreComparedByASCIIFoldingOnly(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"a@x.test", "A@X.TEST", true}, {"a@x.test", "a@x.test", true}, {"a@x.test", "a@x.tesT", true},
		{"a@x.test", "b@x.test", false}, {"a@x.test", "a@x.tes", false}, {"", "", true}, {"a", "", false},
		{"k@x.test", "K@x.test", false}, // Kelvin sign: Unicode folding would equal "k"
		{"@", "`", false}, {"[", "{", false}, {"Z", "z", true}, {"A", "a", true}, {"`", "@", false},
	} {
		if got := asciiEqual(c.a, c.b); got != c.want {
			t.Errorf("asciiEqual(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func newBotDaemon(t *testing.T, b *BotConfig, edit func(*Deps)) (*Daemon, error) {
	t.Helper()
	e := newEnv(t)
	e.cfg.Bot = b
	deps := e.deps()
	deps.OS = "linux"
	deps.ToolRunner = nopRunner{}
	if edit != nil {
		edit(&deps)
	}
	return New(e.cfg, e.dirs, deps)
}

func TestConfiguredBotIsWiredWithItsAllowlistAndOwnerCommands(t *testing.T) {
	d, err := newBotDaemon(t, withTool(t, goodBot(t)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.closeHost()
	if d.host == nil || d.deps.OnInbound == nil {
		t.Fatal("the bot is not wired")
	}
	for owner, want := range map[string]bool{"a@x.test": true, "A@X.TEST": true, "b@x.test": false, "": false, "a@x.test.evil": false} {
		if d.deps.Allow == nil || d.deps.Allow(owner) != want {
			t.Errorf("allow(%q) != %v", owner, want)
		}
	}
	for _, m := range []string{"approvals", "approve", "deny", "tool_calls", "tool_approve", "tool_deny", "tool_revoke"} {
		if d.srv.Methods[m] == nil {
			t.Errorf("method %s is not registered", m)
		}
	}
	// The commands that change what runs are the owner's alone: a bot's process is refused them.
	for _, m := range []string{"approve", "deny", "tool_approve", "tool_deny", "tool_revoke"} {
		if !d.srv.Sensitive[m] {
			t.Errorf("method %s is not sensitive", m)
		}
	}
}

func TestToolLessBotNeedsNoToolMethods(t *testing.T) {
	d, err := newBotDaemon(t, goodBot(t), func(deps *Deps) { deps.ToolRunner = nil })
	if err != nil {
		t.Fatal(err)
	}
	defer d.closeHost()
	if d.srv.Methods["tool_calls"] != nil || d.srv.Methods["approve"] == nil {
		t.Fatal("methods")
	}
	if d.cfg.Bot.Approval != "" {
		t.Fatal("the configuration was changed")
	}
}

func TestStartupFailsClosed(t *testing.T) {
	for name, tc := range map[string]struct {
		bot  func(*BotConfig)
		deps func(*Deps)
		want error
	}{
		"tool-using without owner approval": {func(b *BotConfig) { b.Approval = "none"; b.ToolUsing = true }, nil, skill.ErrNeedsApproval},
		"tools without owner approval":      {func(b *BotConfig) { withTool(t, b).Approval = "none" }, nil, skill.ErrNeedsApproval},
		"tool-using on windows":             {func(b *BotConfig) { b.ToolUsing = true }, func(d *Deps) { d.OS = "windows" }, skill.ErrUnsupportedOS},
		"tools on windows":                  {func(b *BotConfig) { withTool(t, b) }, func(d *Deps) { d.OS = "windows" }, skill.ErrUnsupportedOS},
		"another bot supplied":              {nil, func(d *Deps) { d.Allow = func(string) bool { return true } }, ErrConfig},
		"another inbound supplied":          {nil, func(d *Deps) { d.OnInbound = func(pipeline.Inbound) {} }, ErrConfig},
		"command not usable":                {func(b *BotConfig) { b.Env = []string{"NOEQUALS"} }, nil, ErrConfig},
		"invalid after parse":               {func(b *BotConfig) { b.Tools = []ToolConfig{{Name: "a b", Command: "/x", Dir: "/y"}} }, nil, ErrConfig},
	} {
		b := goodBot(t)
		if tc.bot != nil {
			tc.bot(b)
		}
		d, err := newBotDaemon(t, b, tc.deps)
		if !errors.Is(err, tc.want) || d != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestToolUsingBotDefaultsToOwnerApproval(t *testing.T) {
	for _, mod := range []func(*BotConfig){func(b *BotConfig) { b.ToolUsing = true }, func(b *BotConfig) { withTool(t, b) }} {
		b := goodBot(t)
		mod(b)
		s, err := b.skill()
		if err != nil || s.Approval != "owner" || !s.Uses() {
			t.Fatalf("%+v %v", s, err)
		}
	}
	s, _ := goodBot(t).skill()
	if s.Approval != "" || s.Uses() {
		t.Fatalf("a tool-less bot: %+v", s)
	}
	b := goodBot(t)
	b.ToolUsing, b.Approval = true, "none"
	if s, _ := b.skill(); s.Approval != "none" {
		t.Fatalf("an explicit mode was overridden: %+v", s)
	}
	b = goodBot(t)
	b.Tools = []ToolConfig{{Name: "a b", Command: "/x", Dir: "/y"}}
	if _, err := b.skill(); err == nil {
		t.Fatal("a bad manifest")
	}
}

func TestAuditLinesCarryIDsAndStatesOnly(t *testing.T) {
	e := newEnv(t)
	d, err := New(e.cfg, e.dirs, e.deps())
	if err != nil {
		t.Fatal(err)
	}
	d.auditApproval([16]byte{1}, "APPROVAL_WAITING")
	d.auditTool(toolgate.Event{Task: [16]byte{2}, Call: 3, Tool: "grep", State: toolgate.StateRan})
	d.auditTool(toolgate.Event{Task: [16]byte{2}, Call: 4, Tool: "SECRET payload", State: "free text"})
	out := e.log.String()
	for _, want := range []string{"msg=approval task=01000000000000000000000000000000 state=APPROVAL_WAITING",
		"msg=\"tool call\" task=02000000000000000000000000000000 tool=grep call=3 state=TOOL_RAN"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "SECRET") || strings.Contains(out, "free text") {
		t.Fatalf("free text reached the log:\n%s", out)
	}
}

// The real runner is built from the declared tools: a missing jail or, where there is no sandbox, the sandbox is the
// reason the daemon does not start.
func TestRealToolRunnerIsBuiltFromTheConfiguration(t *testing.T) {
	b := withTool(t, goodBot(t))
	_, err := newToolRunner(b, Dirs{Config: "/nonexistent/c", State: "/nonexistent/s"})
	if err != nil && !errors.Is(err, toolrun.ErrNoSandbox) {
		t.Fatalf("a valid configuration: %v", err)
	}
	if err == nil && runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Fatal("a runner without a sandbox")
	}
	b.Tools[0].Dir = "/nonexistent/jail"
	if _, err := newToolRunner(b, Dirs{}); !errors.Is(err, toolrun.ErrConfig) && !errors.Is(err, toolrun.ErrNoSandbox) {
		t.Fatalf("a missing jail: %v", err)
	}
	// Through New: the real runner on this system, or no daemon.
	d, err := newBotDaemon(t, withTool(t, goodBot(t)), func(deps *Deps) { deps.ToolRunner, deps.OS = nil, "" })
	switch {
	case runtime.GOOS == "windows":
		if !errors.Is(err, skill.ErrUnsupportedOS) {
			t.Fatalf("windows: %v", err)
		}
	case errors.Is(err, toolrun.ErrNoSandbox):
		t.Logf("no sandbox here: %v", err)
	case err != nil:
		t.Fatal(err)
	default:
		d.closeHost()
	}
}
