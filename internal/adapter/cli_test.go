// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/adapter/adaptertest"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/bot/bottest"
)

const helperEnv = "PARLEY_ADAPTER_HELPER"

// TestMain lets this test binary play the bot a CLI adapter runs: the adapter starts os.Args[0] with
// PARLEY_ADAPTER_HELPER=<mode> in its environment.
func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		helper(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helper(mode string) {
	switch mode {
	case "ref":
		adaptertest.ServeStdio(&bottest.Fake{}, os.Stdin, os.Stdout)
	case "exit":
		os.Exit(3)
	case "askexit": // asks, then leaves without reading the answer
		adaptertest.WriteLine(os.Stdout, adaptertest.OutLine{Type: "question", Content: []byte("q")})
		os.Exit(0)
	case "garbage":
		fmt.Println("nonsense")
		time.Sleep(time.Minute)
	case "noline": // endless output without a newline
		buf := []byte(strings.Repeat("A", 1<<16))
		for {
			if _, err := os.Stdout.Write(buf); err != nil {
				return
			}
		}
	case "deaf": // never reads its input, never answers
		time.Sleep(time.Minute)
	case "env":
		adaptertest.WriteLine(os.Stdout, adaptertest.OutLine{Type: "result", Content: []byte(fmt.Sprint(os.Getenv("PARLEY_SECRET"), "|", len(os.Environ()), "|", strings.Join(os.Args[1:], " ")))})
	case "spawn": // a grandchild that keeps writing a heartbeat, then a bot that never answers
		exe, _ := os.Executable()
		child := exec.Command(exe)
		child.Env = []string{helperEnv + "=beat", "PARLEY_BEAT=" + os.Getenv("PARLEY_BEAT")}
		child.Start()
		time.Sleep(time.Minute)
	case "beat":
		f, _ := os.OpenFile(os.Getenv("PARLEY_BEAT"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		for {
			f.Write([]byte("."))
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func self(t testing.TB) string {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func cli(t testing.TB, mode string, extra ...string) *adapter.CLI {
	t.Helper()
	c, err := adapter.NewCLI(adapter.CLIConfig{Command: self(t), Env: append([]string{helperEnv + "=" + mode}, extra...)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCLIMeetsContract(t *testing.T) {
	bottest.Contract(t, func(*testing.T) bot.Bot { return cli(t, "ref") })
}

func TestCLIConfigRejectsUnsafeCommands(t *testing.T) {
	abs := self(t)
	for name, cfg := range map[string]adapter.CLIConfig{
		"empty":          {},
		"relative":       {Command: "bot"},
		"found by PATH":  {Command: "sh"},
		"relative dir":   {Command: abs, Dir: "x"},
		"NUL in command": {Command: abs + "\x00"},
		"NUL in arg":     {Command: abs, Args: []string{"a\x00b"}},
		"NUL in dir":     {Command: abs, Dir: filepath.Dir(abs) + "\x00"},
		"env without =":  {Command: abs, Env: []string{"A"}},
		"env empty name": {Command: abs, Env: []string{"=A"}},
		"NUL in env":     {Command: abs, Env: []string{"A=b\x00"}},
	} {
		if _, err := adapter.NewCLI(cfg); !errors.Is(err, adapter.ErrCLIConfig) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if _, err := adapter.NewCLI(adapter.CLIConfig{Command: abs, Args: []string{"a b", "$(x)", "; rm"}, Dir: filepath.Dir(abs), Env: []string{"A=b=c"}}); err != nil {
		t.Fatal(err)
	}
}

// Nothing from the task is on the command line, and the daemon's environment (credentials) is not the bot's.
func TestCLIGetsNoTaskInItsArgumentsAndNoneOfTheDaemonsEnvironment(t *testing.T) {
	t.Setenv("PARLEY_SECRET", "SECRET-CANARY")
	c, err := adapter.NewCLI(adapter.CLIConfig{Command: self(t), Args: []string{"-fixed", "arg"}, Env: []string{helperEnv + "=env"}})
	if err != nil {
		t.Fatal(err)
	}
	tk := task
	tk.Content = []byte("$(touch pwned); -x")
	res, err := c.Handle(context.Background(), tk, &stub{})
	if err != nil || string(res) != "|1|-fixed arg" {
		t.Fatalf("%q %v", res, err)
	}
}

func TestCLICommandThatCannotStartFailsWithoutNamingIt(t *testing.T) {
	c, err := adapter.NewCLI(adapter.CLIConfig{Command: filepath.Join(t.TempDir(), "SECRET-CANARY-missing")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Handle(context.Background(), task, &stub{})
	if err == nil || strings.Contains(err.Error(), "SECRET-CANARY") {
		t.Fatalf("%v", err)
	}
}

func TestCLIHostileCommands(t *testing.T) {
	for name, mode := range map[string]string{
		"exits at once":           "exit",
		"not the protocol":        "garbage",
		"a line that never ends":  "noline",
		"no final message at EOF": "exit",
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			start := time.Now()
			_, err := cli(t, mode).Handle(ctx, task, &stub{})
			var f *bot.Failure
			if err == nil || errors.As(err, &f) || ctx.Err() != nil {
				t.Fatalf("%v (ctx %v)", err, ctx.Err())
			}
			if time.Since(start) > 10*time.Second {
				t.Fatal("the hostile bot was waited for")
			}
		})
	}
}

// A bot that never reads or answers is ended by the deadline, killed and reaped, with the task line unread.
func TestCLIDeadlineKillsACommandThatNeverReads(t *testing.T) {
	big := task
	big.Content = make([]byte, 4<<20) // more than a pipe holds: the write to the bot blocks
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := cli(t, "deaf").Handle(ctx, big, &stub{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

func TestCLICancelKillsTheWholeProcessTree(t *testing.T) {
	beat := filepath.Join(t.TempDir(), "beat")
	size := func() int64 {
		fi, err := os.Stat(beat)
		if err != nil {
			return 0
		}
		return fi.Size()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := cli(t, "spawn", "PARLEY_BEAT="+beat).Handle(ctx, task, &stub{}); done <- err }()
	for end := time.Now().Add(20 * time.Second); size() < 3; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the grandchild never started")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancel did not end the task")
	}
	time.Sleep(100 * time.Millisecond)
	was := size()
	time.Sleep(300 * time.Millisecond)
	if size() != was {
		t.Fatalf("the grandchild survived the cancel (%s)", runtime.GOOS)
	}
}

func TestCLISessionFailuresEndTheTask(t *testing.T) {
	boom := errors.New("send failed")
	tk := task
	tk.Content = []byte("status s")
	if _, err := cli(t, "ref").Handle(context.Background(), tk, &stub{statErr: boom}); err != boom {
		t.Fatalf("status: %v", err)
	}
	tk.Content = []byte("ask q")
	if _, err := cli(t, "ref").Handle(context.Background(), tk, &stub{askErr: boom}); err != boom {
		t.Fatalf("ask: %v", err)
	}
}

// The command stops reading after its question: the answer cannot be written.
func TestCLIAnswerToACommandThatStoppedReadingFails(t *testing.T) {
	tk := task
	tk.Content = []byte("ask q")
	s := &stub{answer: strings.Repeat("a", 4<<20)}
	if _, err := cli(t, "askexit").Handle(context.Background(), tk, s); err == nil {
		t.Fatal("no error")
	}
}

func TestCLICommandThatCannotBeContainedDoesNotRun(t *testing.T) {
	restore := adapter.SetContain(func(*exec.Cmd) (func(), error) { return nil, errors.New("no job") })
	defer restore()
	beat := filepath.Join(t.TempDir(), "beat")
	if _, err := cli(t, "beat", "PARLEY_BEAT="+beat).Handle(context.Background(), task, &stub{}); err == nil || strings.Contains(err.Error(), "no job") {
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
