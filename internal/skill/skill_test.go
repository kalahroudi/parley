// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package skill_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/approval"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/skill"
)

type counting struct{ n atomic.Int32 }

func (c *counting) Handle(context.Context, bot.Task, bot.Session) ([]byte, error) {
	c.n.Add(1)
	return []byte("done"), nil
}

type quiet struct{}

func (quiet) Status(context.Context, []byte) error        { return nil }
func (quiet) Ask(context.Context, []byte) ([]byte, error) { return nil, errors.New("no") }

func TestCheck(t *testing.T) {
	for _, c := range []struct {
		name string
		s    skill.Skill
		goos string
		want error
	}{
		{"tool-less, none", skill.Skill{Approval: approval.None}, "linux", nil},
		{"tool-less, unset", skill.Skill{}, "linux", nil},
		{"tool-less, owner", skill.Skill{Approval: approval.Owner}, "darwin", nil},
		{"tool-less on windows", skill.Skill{Approval: approval.None}, "windows", nil},
		{"tool-using, owner, linux", skill.Skill{ToolUsing: true, Approval: approval.Owner}, "linux", nil},
		{"tool-using, owner, macos", skill.Skill{ToolUsing: true, Approval: approval.Owner}, "darwin", nil},
		{"tool-using, none", skill.Skill{ToolUsing: true, Approval: approval.None}, "linux", skill.ErrNeedsApproval},
		{"tool-using, unset", skill.Skill{ToolUsing: true}, "darwin", skill.ErrNeedsApproval},
		{"tool-using on windows, owner", skill.Skill{ToolUsing: true, Approval: approval.Owner}, "windows", skill.ErrUnsupportedOS},
		{"tool-using on windows, none", skill.Skill{ToolUsing: true, Approval: approval.None}, "windows", skill.ErrUnsupportedOS},
		{"unknown mode, tool-less", skill.Skill{Approval: "auto"}, "linux", skill.ErrConfig},
		{"unknown mode, tool-using", skill.Skill{ToolUsing: true, Approval: "auto"}, "linux", skill.ErrConfig},
	} {
		if got := skill.Check(c.s, c.goos); !errors.Is(got, c.want) || (c.want == nil && got != nil) {
			t.Errorf("%s: Check = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestLabelsAreFixedAndDistinct(t *testing.T) {
	if got := skill.Label(skill.Skill{}); got != "tool-less" {
		t.Errorf("tool-less label = %q", got)
	}
	l := skill.Label(skill.Skill{ToolUsing: true, Approval: approval.Owner})
	if !strings.HasPrefix(l, "tool-using") || !strings.Contains(l, "owner approves each task") || !strings.Contains(l, "each tool call") {
		t.Errorf("tool-using label = %q", l)
	}
}

func TestGateRefusesWhatCheckRefuses(t *testing.T) {
	b := &counting{}
	if _, err := skill.Gate(b, skill.Skill{ToolUsing: true, Approval: approval.None}, "linux", approval.Config{}); !errors.Is(err, skill.ErrNeedsApproval) {
		t.Errorf("tool-using none: %v", err)
	}
	if _, err := skill.Gate(b, skill.Skill{ToolUsing: true, Approval: approval.Owner}, "windows", approval.Config{}); !errors.Is(err, skill.ErrUnsupportedOS) {
		t.Errorf("windows: %v", err)
	}
	if _, err := skill.Gate(nil, skill.Skill{}, "linux", approval.Config{}); !errors.Is(err, skill.ErrConfig) {
		t.Errorf("nil bot: %v", err)
	}
}

// The gate's mode comes from the skill: a caller-supplied cfg cannot loosen it.
func TestToolUsingSkillRunsOnlyAfterApproval(t *testing.T) {
	b := &counting{}
	g, err := skill.Gate(b, skill.Skill{ToolUsing: true, Approval: approval.Owner}, "linux",
		approval.Config{Mode: approval.None, Bot: &counting{}, Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	_, err = g.Handle(context.Background(), bot.Task{ID: [16]byte{1}, Content: []byte("x")}, quiet{})
	var f *bot.Failure
	if !errors.As(err, &f) || f.Message != approval.TextTimedOut {
		t.Fatalf("unanswered task: %v", err)
	}
	if b.n.Load() != 0 {
		t.Fatal("the tool-using bot ran without approval")
	}
}

func TestToolLessSkillRunsAtOnce(t *testing.T) {
	b := &counting{}
	g, err := skill.Gate(b, skill.Skill{Approval: approval.None}, "windows", approval.Config{Mode: approval.Owner})
	if err != nil {
		t.Fatal(err)
	}
	out, err := g.Handle(context.Background(), bot.Task{ID: [16]byte{2}}, quiet{})
	if err != nil || string(out) != "done" || b.n.Load() != 1 {
		t.Fatalf("out=%q err=%v runs=%d", out, err, b.n.Load())
	}
}

func TestToolUsingSkillRunsAfterTheOwnerApproves(t *testing.T) {
	b := &counting{}
	g, err := skill.Gate(b, skill.Skill{ToolUsing: true, Approval: approval.Owner}, "darwin", approval.Config{})
	if err != nil {
		t.Fatal(err)
	}
	id := [16]byte{3}
	type res struct {
		out []byte
		err error
	}
	done := make(chan res, 1)
	go func() {
		out, err := g.Handle(context.Background(), bot.Task{ID: id}, quiet{})
		done <- res{out, err}
	}()
	for deadline := time.Now().Add(5 * time.Second); len(g.List()) == 0; {
		if time.Now().After(deadline) {
			t.Fatal("the task never waited for approval")
		}
		time.Sleep(time.Millisecond)
	}
	if b.n.Load() != 0 {
		t.Fatal("the bot ran before approval")
	}
	if err := g.Decide(id, true); err != nil {
		t.Fatal(err)
	}
	if r := <-done; r.err != nil || string(r.out) != "done" || b.n.Load() != 1 {
		t.Fatalf("out=%q err=%v runs=%d", r.out, r.err, b.n.Load())
	}
}
