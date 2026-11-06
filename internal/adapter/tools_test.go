// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/botproc"
)

// recordingTools is the Tools a CLI gets in these tests.
type recordingTools struct {
	mu    sync.Mutex
	calls []string
	ended [][16]byte
	reply adapter.ToolReply
	err   error
	wait  bool
}

func (r *recordingTools) Call(_ context.Context, t bot.Task, tool string, args []string, onWait func()) (adapter.ToolReply, error) {
	r.mu.Lock()
	r.calls = append(r.calls, fmt.Sprintf("%x|%s|%q", t.ID[:1], tool, args))
	r.mu.Unlock()
	if r.wait {
		onWait()
	}
	rep := r.reply
	rep.Content = append([]byte(nil), rep.Content...) // the adapter clears what it is given
	return rep, r.err
}

func (r *recordingTools) End(id [16]byte) { r.mu.Lock(); r.ended = append(r.ended, id); r.mu.Unlock() }

func cliTools(t *testing.T, tools adapter.Tools, mode string, extra ...string) *adapter.CLI {
	t.Helper()
	c, err := adapter.NewCLI(adapter.CLIConfig{Command: self(t), Env: append([]string{helperEnv + "=" + mode}, extra...), Tools: tools})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCLIServesToolRequestsThroughTools(t *testing.T) {
	rt := &recordingTools{reply: adapter.ToolReply{Outcome: "ok", Exit: 0, Content: []byte("framed output")}, wait: true}
	s := &stub{}
	res, err := cliTools(t, rt, "tooler", "PARLEY_TOOL=grep", "PARLEY_ARGS=-n,a b", "PARLEY_N=2").Handle(context.Background(), task, s)
	if err != nil {
		t.Fatal(err)
	}
	var line struct {
		Type, ID, Outcome string
		Turn              int
		Untrusted         bool
		Content           []byte
	}
	if err := json.Unmarshal(res, &line); err != nil || line.Type != "tool_result" || line.Turn != 2 || line.Outcome != "ok" || !line.Untrusted ||
		string(line.Content) != "framed output" || line.ID != "ab000000000000000000000000000000" {
		t.Fatalf("%s %v", res, err)
	}
	if len(rt.calls) != 2 || rt.calls[0] != `ab|grep|["-n" "a b"]` || len(rt.ended) != 1 || rt.ended[0][0] != 0xab {
		t.Fatalf("calls %v ended %v", rt.calls, rt.ended)
	}
	if len(s.statuses) != 2 || s.statuses[0] != adapter.TextToolWaiting {
		t.Fatalf("statuses %q", s.statuses)
	}
}

// A CLI configured without Tools is tool-less: asking for a tool is a protocol error that ends the task.
func TestCLIWithoutToolsRefusesToolRequests(t *testing.T) {
	_, err := cli(t, "tooler", "PARLEY_TOOL=rm", "PARLEY_ARGS=-rf", "PARLEY_N=1").Handle(context.Background(), task, &stub{})
	var f *bot.Failure
	if err == nil || errors.As(err, &f) {
		t.Fatalf("%v", err)
	}
}

func TestCLIToolRequestsAreBounded(t *testing.T) {
	rt := &recordingTools{}
	_, err := cliTools(t, rt, "tooler", "PARLEY_TOOL=t", "PARLEY_ARGS=a", fmt.Sprint("PARLEY_N=", adapter.MaxToolRequests+3)).Handle(context.Background(), task, &stub{})
	if err == nil || len(rt.calls) != adapter.MaxToolRequests || len(rt.ended) != 1 {
		t.Fatalf("%v after %d calls, ended %d", err, len(rt.calls), len(rt.ended))
	}
}

func TestCLIToolFailuresEndTheTask(t *testing.T) {
	boom := errors.New("boom")
	if _, err := cliTools(t, &recordingTools{err: boom}, "tooler", "PARLEY_TOOL=t", "PARLEY_ARGS=a", "PARLEY_N=1").Handle(context.Background(), task, &stub{}); err != boom {
		t.Fatalf("call: %v", err)
	}
	// The command asked and left: the reply cannot be written. The big reply fills the pipe, so the write fails.
	rt := &recordingTools{reply: adapter.ToolReply{Outcome: "ok", Content: []byte(strings.Repeat("a", 1<<20))}}
	if _, err := cliTools(t, rt, "toolgone").Handle(context.Background(), task, &stub{}); err == nil {
		t.Fatal("no error")
	}
}

func run(t *testing.T, ctx context.Context, limit int, mode string, extra ...string) (adapter.RunResult, error) {
	t.Helper()
	cmd := exec.Command(self(t))
	cmd.Env = append([]string{helperEnv + "=" + mode}, extra...)
	return adapter.RunContained(ctx, cmd, limit)
}

func TestRunContainedCapturesOutputAndExit(t *testing.T) {
	r, err := run(t, context.Background(), 100, "out", "PARLEY_OUT=hello", "PARLEY_EXIT=0")
	if err != nil || string(r.Output) != "hello" || r.Truncated || r.Exit != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = run(t, context.Background(), 5, "out", "PARLEY_OUT=hello", "PARLEY_EXIT=7")
	if err != nil || string(r.Output) != "hello" || r.Truncated || r.Exit != 7 {
		t.Fatalf("exactly the limit, status 7: %+v %v", r, err)
	}
	r, err = run(t, context.Background(), 4, "out", "PARLEY_OUT=hello", "PARLEY_EXIT=0")
	if err != nil || string(r.Output) != "hell" || !r.Truncated {
		t.Fatalf("over the limit: %+v %v", r, err)
	}
	// A command with no end to its output is cut and killed at the limit.
	start := time.Now()
	r, err = run(t, context.Background(), 1000, "noline")
	if err != nil || len(r.Output) != 1000 || !r.Truncated || (r.Exit != -1 && runtime.GOOS != "windows") || time.Since(start) > 15*time.Second { // Windows reports a job kill as status 1
		t.Fatalf("%d bytes %+v %v", len(r.Output), r.Truncated, err)
	}
}

func TestRunContainedKillsWhatTheCommandStartedWhenItFinishes(t *testing.T) {
	beat := filepath.Join(t.TempDir(), "beat")
	r, err := run(t, context.Background(), 100, "spawnexit", "PARLEY_BEAT="+beat)
	if err != nil || string(r.Output) != "done" || r.Exit != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	size := func() int64 {
		fi, _ := os.Stat(beat)
		if fi == nil {
			return 0
		}
		return fi.Size()
	}
	time.Sleep(100 * time.Millisecond)
	was := size()
	time.Sleep(300 * time.Millisecond)
	if size() != was {
		t.Fatal("a process the command started outlived it")
	}
}

func TestRunContainedEndsWithItsContext(t *testing.T) {
	beat := filepath.Join(t.TempDir(), "beat")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var res adapter.RunResult
	go func() {
		var err error
		res, err = run(t, ctx, 100, "spawn", "PARLEY_BEAT="+beat)
		done <- err
	}()
	for end := time.Now().Add(20 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if fi, _ := os.Stat(beat); fi != nil && fi.Size() >= 3 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the grandchild never started")
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || res.Exit != -1 {
		t.Fatalf("%+v %v", res, err)
	}
	time.Sleep(100 * time.Millisecond)
	fi, _ := os.Stat(beat)
	was := fi.Size()
	time.Sleep(300 * time.Millisecond)
	if fi, _ = os.Stat(beat); fi.Size() != was {
		t.Fatal("the grandchild survived the cancel")
	}
}

func TestRunContainedRefusesWhatCannotStartOrBeContained(t *testing.T) {
	cmd := exec.Command(filepath.Join(t.TempDir(), "SECRET-CANARY-missing"))
	if _, err := adapter.RunContained(context.Background(), cmd, 10); err == nil || strings.Contains(err.Error(), "SECRET-CANARY") {
		t.Fatalf("%v", err)
	}
	restore := adapter.SetContain(func(*exec.Cmd) (func(), error) { return nil, errors.New("no job") })
	defer restore()
	beat := filepath.Join(t.TempDir(), "beat")
	if _, err := run(t, context.Background(), 10, "beat", "PARLEY_BEAT="+beat); err == nil || strings.Contains(err.Error(), "no job") {
		t.Fatalf("%v", err)
	}
	time.Sleep(100 * time.Millisecond)
	fi, _ := os.Stat(beat)
	was := int64(0)
	if fi != nil {
		was = fi.Size()
	}
	time.Sleep(300 * time.Millisecond)
	if fi, _ = os.Stat(beat); fi != nil && fi.Size() != was {
		t.Fatal("the command that could not be contained is still running")
	}
}

// A tool process is registered with the daemon's registry from the moment it starts until it is reaped, exactly like a bot,
// so the daemon refuses it the commands that change what it trusts.
func TestRunContainedRegistersTheCommandWhileItRuns(t *testing.T) {
	pids := make(chan int, 1)
	restore := adapter.SetContain(func(cmd *exec.Cmd) (func(), error) {
		pids <- cmd.Process.Pid
		return func() { _ = cmd.Process.Kill() }, nil
	})
	defer restore()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go run(t, ctx, 10, "deaf")
	pid := <-pids
	own, err := botproc.Default.Owns(pid)
	if !own && !errors.Is(err, botproc.ErrUnknown) { // on Windows the job is not tracked by the stand-in, which is refused too
		t.Errorf("the running command is not registered: %v %v", own, err)
	}
	if runtime.GOOS != "windows" && (!own || err != nil) {
		t.Errorf("the running command is not taken for a bot: %v %v", own, err)
	}
}
