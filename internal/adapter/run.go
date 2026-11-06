// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"errors"
	"io"
	"os/exec"

	"github.com/kalahroudi/parley/internal/botproc"
)

// RunResult is what RunContained returns.
type RunResult struct {
	Output    []byte // at most the limit
	Truncated bool   // the command wrote more and was killed
	Exit      int    // the exit status; -1 if it was killed or did not exit by itself
}

// RunContained runs cmd to completion under the same containment as a CLI bot, for a program the daemon runs on a bot's
// behalf (a tool): it is started in a session of its own with no controlling terminal (Unix) or in a job object with no
// console (Windows), registered with botproc before the daemon can see a connection from it (so it can never approve
// anything, see botproc), killed together with everything it started when ctx ends, when it writes more than limit bytes
// or when it has finished, and reaped. cmd must be built by the caller with an absolute path, a fixed argument list and an
// explicit environment; its standard input is empty and its standard error is discarded.
func RunContained(ctx context.Context, cmd *exec.Cmd, limit int) (RunResult, error) {
	cmd.Stdin, cmd.Stdout, cmd.Stderr, cmd.WaitDelay = nil, nil, nil, reapDelay
	prepare(cmd)
	stdout, _ := cmd.StdoutPipe() // cannot fail: no Stdout is set and the command is not started
	var kill func()
	var cerr error
	remove, serr := botproc.Default.Launch(func() (int, error) {
		if err := cmd.Start(); err != nil {
			return 0, err
		}
		kill, cerr = contain(cmd)
		return cmd.Process.Pid, nil
	})
	if serr != nil {
		return RunResult{}, errors.New("adapter: the command could not be started") // the OS text names the path
	}
	defer remove() // after the command is reaped
	p := &cliPeer{cmd: cmd, kill: kill}
	defer p.close() // also on the early returns below
	if cerr != nil {
		_ = cmd.Process.Kill() // a command that cannot be contained does not run
		return RunResult{}, errors.New("adapter: the command could not be contained")
	}
	defer context.AfterFunc(ctx, p.terminate)()
	out, _ := io.ReadAll(io.LimitReader(stdout, int64(limit)+1)) // a read error is the command being killed: the exit tells
	res := RunResult{Output: out}
	if len(out) > limit {
		res.Output, res.Truncated = out[:limit], true
		p.terminate()
	}
	err := p.reap()
	var ee *exec.ExitError
	switch {
	case ctx.Err() != nil:
		res.Exit = -1
	case errors.As(err, &ee):
		res.Exit = ee.ExitCode() // -1 if a signal ended it
	case err != nil:
		res.Exit = -1
	}
	return res, ctx.Err()
}
