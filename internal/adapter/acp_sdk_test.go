// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/coder/acp-go-sdk"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/bot"
)

// The conformance tests run the adapter against an agent built on the ACP project's Go SDK (github.com/coder/acp-go-sdk,
// generated from the protocol's schema; a test-only dependency, pinned in go.mod, that no shipped program links). The SDK
// decodes and validates every message the adapter sends as the schema's own types and encodes every message the agent
// sends, so an adapter that sends an invalid initialize, session/new, session/prompt or session/cancel, or that
// misreads a valid reply, fails here.

type sdkAgent struct {
	sdk.Agent // the methods this agent does not offer: calling one is a failure of the test
	conn      *sdk.AgentSideConnection
	scenario  string
	path      string // the file the agent reads and writes
	mark      string // a file the agent writes when it is canceled

	mu      sync.Mutex
	cancels map[string]context.CancelFunc
	turn    int
	prompts []string
}

func sdkAgentMain() {
	a := &sdkAgent{scenario: os.Getenv("PARLEY_SDK"), path: os.Getenv("PARLEY_FILE"), mark: os.Getenv("PARLEY_MARK"), cancels: map[string]context.CancelFunc{}}
	a.conn = sdk.NewAgentSideConnection(a, os.Stdout, os.Stdin)
	<-a.conn.Done()
}

func (a *sdkAgent) Initialize(_ context.Context, p sdk.InitializeRequest) (sdk.InitializeResponse, error) {
	if p.ProtocolVersion != sdk.ProtocolVersionNumber {
		return sdk.InitializeResponse{}, fmt.Errorf("version %d", p.ProtocolVersion)
	}
	a.prompts = append(a.prompts, fmt.Sprintf("fs=%v/%v terminal=%v client=%s", p.ClientCapabilities.Fs.ReadTextFile, p.ClientCapabilities.Fs.WriteTextFile, p.ClientCapabilities.Terminal, p.ClientInfo.Name))
	return sdk.InitializeResponse{ProtocolVersion: sdk.ProtocolVersionNumber}, nil
}

func (a *sdkAgent) Authenticate(context.Context, sdk.AuthenticateRequest) (sdk.AuthenticateResponse, error) {
	return sdk.AuthenticateResponse{}, nil
}

func (a *sdkAgent) NewSession(_ context.Context, p sdk.NewSessionRequest) (sdk.NewSessionResponse, error) {
	if !filepath.IsAbs(p.Cwd) || len(p.McpServers) != 0 {
		return sdk.NewSessionResponse{}, fmt.Errorf("cwd %q, %d servers", p.Cwd, len(p.McpServers))
	}
	return sdk.NewSessionResponse{SessionId: "sdk-1"}, nil
}

func (a *sdkAgent) Cancel(_ context.Context, p sdk.CancelNotification) error {
	a.mu.Lock()
	cancel := a.cancels[string(p.SessionId)]
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

func (a *sdkAgent) say(ctx context.Context, sid sdk.SessionId, text string) error {
	return a.conn.SessionUpdate(ctx, sdk.SessionNotification{SessionId: sid, Update: sdk.UpdateAgentMessageText(text)})
}

func (a *sdkAgent) Prompt(ctx context.Context, p sdk.PromptRequest) (sdk.PromptResponse, error) {
	a.mu.Lock()
	a.turn++
	turn := a.turn
	a.mu.Unlock()
	if len(p.Prompt) != 1 || p.Prompt[0].Text == nil {
		return sdk.PromptResponse{}, errors.New("the prompt is not one text block")
	}
	text := p.Prompt[0].Text.Text
	meta, _ := json.Marshal(p.Meta)
	switch a.scenario {
	case "cancel":
		cctx, cancel := context.WithCancel(ctx)
		a.mu.Lock()
		a.cancels[string(p.SessionId)] = cancel
		a.mu.Unlock()
		<-cctx.Done()
		os.WriteFile(a.mark, []byte("canceled"), 0o600)
		return sdk.PromptResponse{StopReason: sdk.StopReasonCancelled}, nil
	case "question":
		if turn == 1 {
			if err := a.say(ctx, p.SessionId, "which one?"); err != nil {
				return sdk.PromptResponse{}, err
			}
			return sdk.PromptResponse{StopReason: sdk.StopReasonEndTurn, Meta: map[string]any{"parley": map[string]any{"inputRequired": true}}}, nil
		}
		return sdk.PromptResponse{StopReason: sdk.StopReasonEndTurn}, a.say(ctx, p.SessionId, "you said "+text+" "+string(meta))
	case "failure":
		return sdk.PromptResponse{}, &sdk.RequestError{Code: -32000, Message: "no such file", Data: map[string]any{"parley": "failure"}}
	case "refusal":
		return sdk.PromptResponse{StopReason: sdk.StopReasonRefusal}, nil
	}
	// "flow": a plan, a permission request, a read, a write and a terminal request, then a summary.
	if err := a.conn.SessionUpdate(ctx, sdk.SessionNotification{SessionId: p.SessionId, Update: sdk.UpdatePlan(
		sdk.PlanEntry{Content: "reading the file", Priority: sdk.PlanEntryPriorityMedium, Status: sdk.PlanEntryStatusInProgress})}); err != nil {
		return sdk.PromptResponse{}, err
	}
	title, kind := "Write the file", sdk.ToolKindEdit
	perm, err := a.conn.RequestPermission(ctx, sdk.RequestPermissionRequest{SessionId: p.SessionId,
		ToolCall: sdk.ToolCallUpdate{ToolCallId: "c1", Title: &title, Kind: &kind},
		Options: []sdk.PermissionOption{
			{Kind: sdk.PermissionOptionKindAllowAlways, Name: "Always", OptionId: "always"},
			{Kind: sdk.PermissionOptionKindAllowOnce, Name: "Allow", OptionId: "ok"},
			{Kind: sdk.PermissionOptionKindRejectOnce, Name: "Reject", OptionId: "no"}}})
	outcome := "error"
	if err == nil && perm.Outcome.Selected != nil {
		outcome = string(perm.Outcome.Selected.OptionId)
	} else if err == nil && perm.Outcome.Cancelled != nil {
		outcome = "cancelled"
	}
	line, limit := 2, 1
	rd, rerr := a.conn.ReadTextFile(ctx, sdk.ReadTextFileRequest{SessionId: p.SessionId, Path: a.path, Line: &line, Limit: &limit})
	_, werr := a.conn.WriteTextFile(ctx, sdk.WriteTextFileRequest{SessionId: p.SessionId, Path: a.path + ".out", Content: "written"})
	_, terr := a.conn.CreateTerminal(ctx, sdk.CreateTerminalRequest{SessionId: p.SessionId, Command: "ls"})
	var re *sdk.RequestError
	termCode := 0
	if errors.As(terr, &re) {
		termCode = re.Code
	}
	summary := fmt.Sprintf("%s|prompt=%s|meta=%s|perm=%s|read=%q err=%v|write err=%v|terminal=%d", a.prompts[0], text, meta, outcome, rd.Content, rerr != nil, werr != nil, termCode)
	return sdk.PromptResponse{StopReason: sdk.StopReasonEndTurn}, a.say(ctx, p.SessionId, summary)
}

func sdkACP(t *testing.T, g adapter.Tools, dir, scenario string, extra ...string) *adapter.ACP {
	t.Helper()
	a, err := adapter.NewACP(adapter.ACPConfig{Command: self(t), Dir: dir, Gate: g, Env: append([]string{helperEnv + "=acp-sdk", "PARLEY_SDK=" + scenario}, extra...)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// initialize, session/new, session/prompt, a plan, a permission request, a file read and write and a terminal request,
// against the SDK's agent: with a gate that says yes, and with one that says no.
func TestACPConformsToTheSDKAgent(t *testing.T) {
	for _, yes := range []bool{true, false} {
		t.Run(fmt.Sprintf("owner says %v", yes), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "f.txt")
			writeFile(t, path, "one\ntwo\nthree\n")
			g := &fakeGate{allow: func(string, []string) bool { return yes }}
			s := &stub{}
			out := playOK(t, sdkACP(t, g, dir, "flow", "PARLEY_FILE="+path), task, s)
			perm, read, wrote := "no", `"two\n" err=false`, "false"
			if yes {
				perm = "ok"
			} else {
				read, wrote = `"" err=true`, "true"
			}
			meta := `{"parley":{"caller":"dev-a","context":"ctx-1","expires":"2030-01-02T03:04:05Z","owner":"a@example.com","task":"ab000000000000000000000000000000"}}`
			want := fmt.Sprintf("fs=true/true terminal=false client=parley|prompt=echo hi|meta=%s|perm=%s|read=%s|write err=%s|terminal=-32601", meta, perm, read, wrote)
			if out != want {
				t.Fatalf("%s\nwant %s", out, want)
			}
			if len(s.statuses) != 1 || s.statuses[0] != "reading the file" {
				t.Fatalf("statuses %q", s.statuses)
			}
			if _, err := os.Stat(path + ".out"); (err == nil) != yes {
				t.Fatalf("the written file exists: %v", err == nil)
			}
		})
	}
}

func TestACPConformsToTheSDKAgentWithoutAGate(t *testing.T) {
	out := playOK(t, sdkACP(t, nil, t.TempDir(), "flow", "PARLEY_FILE=/nowhere"), task, &stub{})
	if !strings.HasPrefix(out, "fs=false/false terminal=false client=parley|") || !strings.Contains(out, "|perm=no|read=\"\" err=true|write err=true|terminal=-32601") {
		t.Fatal(out)
	}
}

func TestACPQuestionAgainstTheSDKAgent(t *testing.T) {
	s := &stub{answer: "blue"}
	out := playOK(t, sdkACP(t, nil, t.TempDir(), "question"), task, s)
	if len(s.asked) != 1 || s.asked[0] != "which one?" || out != `you said blue {"parley":{"answer":true,"task":"ab000000000000000000000000000000"}}` {
		t.Fatalf("%q %q", s.asked, out)
	}
}

func TestACPFailuresAgainstTheSDKAgent(t *testing.T) {
	var f *bot.Failure
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := sdkACP(t, nil, t.TempDir(), "failure").Handle(ctx, task, &stub{}); !errors.As(err, &f) || f.Message != "no such file" {
		t.Fatalf("%v", err)
	}
	if _, err := sdkACP(t, nil, t.TempDir(), "refusal").Handle(ctx, task, &stub{}); !errors.As(err, &f) || f.Message != adapter.TextACPRefused {
		t.Fatalf("%v", err)
	}
}

// session/cancel reaches the SDK's agent, which ends its turn with the stop reason "cancelled" before it is killed.
func TestACPCancelAgainstTheSDKAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the marker is written after the pipe closes on Windows") // the kill is immediate there
	}
	mark := filepath.Join(t.TempDir(), "mark")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := sdkACP(t, nil, t.TempDir(), "cancel", "PARLEY_MARK="+mark).Handle(ctx, task, &stub{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if b, _ := os.ReadFile(mark); string(b) == "canceled" {
			return
		}
	}
	t.Fatal("the agent was not told to cancel")
}
