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
	cmd := exec.Command(c.cfg.Command, c.cfg.Args...) // no shell, no PATH lookup (the path is absolute)
	cmd.Env, cmd.Dir, cmd.WaitDelay = c.cfg.Env, c.cfg.Dir, reapDelay
	prepare(cmd)
	stdin, _ := cmd.StdinPipe()   // cannot fail: no Stdin is set and the command is not started
	stdout, _ := cmd.StdoutPipe() // likewise
	if err := cmd.Start(); err != nil {
		return nil, errors.New("adapter: the bot command could not be started") // the OS text names the path
	}
	kill, err := contain(cmd)
	p := &cliPeer{cmd: cmd, id: t.ID, in: stdin, r: bufio.NewReaderSize(stdout, 64<<10), kill: kill}
	defer p.close()
	if err != nil {
		_ = cmd.Process.Kill() // a bot that cannot be contained does not run
		return nil, errors.New("adapter: the bot command could not be contained")
	}
	// Canceling (or the deadline) kills the command, which unblocks a read or write that is waiting on it.
	defer context.AfterFunc(ctx, p.terminate)()
	line := taskLine(t)
	p.scrub = append(p.scrub, line)
	if err := p.write(ctx, line); err != nil {
		return nil, err
	}
	return converse(ctx, p, s)
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
	p.in.Close()
	p.terminate()
	p.mu.Lock()
	p.done = true
	p.mu.Unlock()
	_ = p.cmd.Wait()
	for _, l := range p.scrub {
		clear(l)
	}
}
