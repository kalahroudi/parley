// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/botproc"
)

// ErrCLIConfig means the CLI adapter's command, directory or environment is not acceptable.
var ErrCLIConfig = errors.New("adapter: invalid CLI configuration")

// contain is containTree, replaceable so that its failure can be tested on systems where it cannot fail.
var contain = containTree

// reapDelay bounds how long Handle waits for the pipes of a killed command to drain.
const reapDelay = 2 * time.Second

// CLIConfig configures the CLI adapter.
type CLIConfig struct {
	// Command is the absolute path of the program that is the bot. It is run directly, never through a shell and
	// never found through PATH or the working directory.
	Command string
	// Args are fixed arguments from the configuration. Nothing from a task ever reaches the command line.
	Args []string
	// Dir is the working directory (absolute), or empty for the daemon's.
	Dir string
	// Env is the whole environment of the command ("NAME=value"). The daemon's own environment, which may hold
	// credentials, is never inherited.
	Env []string
	// Tools, if set, runs the tools the bot asks for (only after the owner approved them, see internal/toolgate). Without
	// it a request for a tool is a protocol error and ends the task: the bot is tool-less.
	Tools Tools
}

// CLI is a bot run as a child process per task: the task goes to its standard input and its answers come back on its
// standard output, in the line protocol of the package comment. Its standard error is discarded.
type CLI struct{ cfg CLIConfig }

// NewCLI validates cfg and returns the adapter.
func NewCLI(cfg CLIConfig) (*CLI, error) {
	bad := !filepath.IsAbs(cfg.Command) || (cfg.Dir != "" && !filepath.IsAbs(cfg.Dir))
	for _, a := range cfg.Args {
		bad = bad || strings.ContainsRune(a, 0)
	}
	for _, e := range cfg.Env {
		bad = bad || !strings.Contains(e, "=") || strings.HasPrefix(e, "=") || strings.ContainsRune(e, 0)
	}
	if bad || strings.ContainsRune(cfg.Command, 0) || strings.ContainsRune(cfg.Dir, 0) {
		return nil, ErrCLIConfig
	}
	cfg.Args = append([]string(nil), cfg.Args...)
	cfg.Env = append([]string{}, cfg.Env...) // non-nil: an empty environment, not the daemon's
	return &CLI{cfg: cfg}, nil
}

// Handle implements bot.Bot.
func (c *CLI) Handle(ctx context.Context, t bot.Task, s bot.Session) ([]byte, error) {
	p, stop, err := startBot(ctx, c.cfg, t.ID, nil)
	if err != nil {
		return nil, err
	}
	defer stop()
	line := taskLine(t)
	p.scrub = append(p.scrub, line)
	if err := p.write(ctx, line); err != nil {
		return nil, err
	}
	var tc *toolConv
	if c.cfg.Tools != nil {
		defer c.cfg.Tools.End(t.ID)
		tc = &toolConv{tools: c.cfg.Tools, task: t, send: func(ctx context.Context, line []byte) error {
			p.scrub = append(p.scrub, line)
			return p.write(ctx, line)
		}}
	}
	return converse(ctx, p, s, tc)
}

// startBot starts the command of cfg for one task, contained and registered (see botproc), and returns it with the
// function that ends the task's use of it: the command is killed with everything it started, reaped and unregistered,
// and the lines written to it are scrubbed. Canceling ctx (or its deadline) kills the command, which unblocks a read or
// write that is waiting on it; onCancel, if given, does that itself (it must see to the kill) and stop waits for it. A
// command that cannot be started or contained does not run.
func startBot(ctx context.Context, cfg CLIConfig, id [16]byte, onCancel func(*cliPeer)) (*cliPeer, func(), error) {
	cmd := exec.Command(cfg.Command, cfg.Args...) // no shell, no PATH lookup (the path is absolute)
	cmd.Env, cmd.Dir, cmd.WaitDelay = cfg.Env, cfg.Dir, reapDelay
	prepare(cmd)
	stdin, _ := cmd.StdinPipe()   // cannot fail: no Stdin is set and the command is not started
	stdout, _ := cmd.StdoutPipe() // likewise
	// The bot is registered before the daemon can see a connection from it, so it can never approve its own tasks (see botproc).
	var kill func()
	var err error
	remove, serr := botproc.Default.Launch(func() (int, error) {
		if err := cmd.Start(); err != nil {
			return 0, err
		}
		kill, err = contain(cmd)
		return cmd.Process.Pid, nil
	})
	if serr != nil {
		return nil, nil, errors.New("adapter: the bot command could not be started") // the OS text names the path
	}
	p := &cliPeer{cmd: cmd, id: id, in: stdin, r: bufio.NewReaderSize(stdout, readBuffer), kill: kill}
	if err != nil {
		_ = cmd.Process.Kill() // a bot that cannot be contained does not run
		p.close()
		remove()
		return nil, nil, errors.New("adapter: the bot command could not be contained")
	}
	fired := make(chan struct{})
	unhook := context.AfterFunc(ctx, func() {
		defer close(fired)
		if onCancel == nil {
			p.terminate()
			return
		}
		onCancel(p)
	})
	return p, func() {
		started := !unhook()
		p.close() // the command is reaped before it is unregistered
		if started {
			<-fired
		}
		remove()
	}, nil
}

type cliPeer struct {
	cmd   *exec.Cmd
	id    [16]byte
	in    io.WriteCloser
	r     *bufio.Reader
	kill  func()
	mu    sync.Mutex
	done  bool // the command has been reaped: its pid may be reused, so it is never signaled again
	scrub [][]byte
}

// terminate kills the command and everything it started, once, and never after it has been reaped.
func (p *cliPeer) terminate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.done && p.kill != nil {
		p.kill()
		p.kill = nil
	}
}

func (p *cliPeer) write(ctx context.Context, line []byte) error {
	if _, err := p.in.Write(line); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("adapter: the bot command stopped reading")
	}
	return nil
}

func (p *cliPeer) next() (message, error) { return readMessage(p.r) }

func (p *cliPeer) answer(ctx context.Context, turn int, content []byte) error {
	line := answerLine(p.id, turn, content)
	p.scrub = append(p.scrub, line)
	return p.write(ctx, line)
}

// close ends the exchange: the command is killed whether or not it finished (a final message has been delivered, or
// the task is over), then reaped, so no process, pipe or goroutine outlives the task.
func (p *cliPeer) close() {
	if p.in != nil {
		p.in.Close()
	}
	_ = p.reap()
	for _, l := range p.scrub {
		clear(l)
	}
}

// reap kills the command and everything it started (once), marks it reaped so that its pid is never signaled again, and
// waits for it. It returns Wait's error.
func (p *cliPeer) reap() error {
	p.terminate()
	p.mu.Lock()
	p.done = true
	p.mu.Unlock()
	return p.cmd.Wait()
}
