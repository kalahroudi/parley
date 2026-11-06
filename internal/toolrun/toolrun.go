// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package toolrun runs the tools that internal/toolgate approved, with least privilege. It is the Runner the daemon gives
// the broker. Each call is one process:
//
//   - started directly from an absolute path with a fixed argument list followed by the approved arguments: no shell, no PATH
//     lookup, so an argument is one argument whatever it contains;
//   - with an environment that is only what the configuration lists, never the daemon's;
//   - in a working directory of the tool's own (the jail), the only place it may write: the rest of the file system is
//     read-only, and the directories the daemon keeps its socket, keys and state in are hidden from it;
//   - without the network unless the manifest declares the tool needs it (and the owner approved that call), and never
//     with a connection to a Unix-domain socket, which is how the daemon is reached;
//   - under the containment of the CLI adapter (internal/adapter.RunContained): in a session of its own with no controlling
//     terminal, registered with botproc so that it can never approve anything, its output cut at the tool's limit, and
//     it, with everything it started, killed and reaped when the call ends, is canceled or runs out of time.
//
// The file-system, network and socket limits are enforced by the operating system's sandbox: bubblewrap on Linux and
// sandbox-exec on macOS. Where neither exists (Windows, or Linux without bubblewrap or user namespaces) New fails: a tool
// that cannot be confined is not run, there is no unsandboxed fallback.
//
// What it does not do: the sandbox keeps the tool from writing outside its jail, from the network and from the daemon's
// directories; it does not hide the rest of the file system from reading (the tool runs as the owner's user), so a tool
// approved to read files can read what the owner can read. Approval is the owner's judgment of that.
package toolrun

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/toolgate"
)

// ErrConfig means a tool's command, directory, environment or arguments are not acceptable.
var ErrConfig = errors.New("toolrun: invalid tool configuration")

// ErrNoSandbox means this system has no sandbox to run tools in, so none is run.
var ErrNoSandbox = errors.New("toolrun: no sandbox is available here (needs bubblewrap on Linux or sandbox-exec on macOS)")

// Spec is how one tool is run.
type Spec struct {
	// Command is the absolute path of the program. It is run directly.
	Command string
	// Args come first on the command line; the approved arguments follow.
	Args []string
	// Dir is the jail: an existing absolute directory, the working directory and the only writable place.
	Dir string
	// Env is the whole environment ("NAME=value").
	Env []string
}

// Config sets a Runner.
type Config struct {
	// Specs maps a manifest tool name to how it runs. Every manifest tool needs one.
	Specs map[string]Spec
	// Hide lists directories to keep from every tool: the daemon's configuration and state directories.
	Hide []string
}

// Runner implements toolgate.Runner.
type Runner struct {
	specs map[string]Spec
	box   boxer
}

// boxer puts a command in the sandbox: it returns the program and arguments to start instead.
type boxer interface {
	wrap(s Spec, args []string, network bool) (path string, argv []string)
}

// New validates cfg and finds the sandbox.
func New(cfg Config) (*Runner, error) {
	box, err := findSandbox(cfg.Hide)
	if err != nil {
		return nil, err
	}
	return newRunner(cfg.Specs, box)
}

// newRunner validates the tools; the tests use it with a box of their own.
func newRunner(in map[string]Spec, box boxer) (*Runner, error) {
	specs := make(map[string]Spec, len(in))
	for name, s := range in {
		jail, err := absDir(s.Dir)
		if err != nil || !filepath.IsAbs(s.Command) || strings.ContainsRune(s.Command, 0) {
			return nil, ErrConfig
		}
		bad := false
		for _, a := range s.Args {
			bad = bad || strings.ContainsRune(a, 0)
		}
		for _, e := range s.Env {
			bad = bad || !strings.Contains(e, "=") || strings.HasPrefix(e, "=") || strings.ContainsRune(e, 0)
		}
		if bad {
			return nil, ErrConfig
		}
		s.Dir = jail
		s.Args = append([]string(nil), s.Args...)
		s.Env = append([]string{}, s.Env...) // non-nil: an empty environment, not the daemon's
		specs[name] = s
	}
	return &Runner{specs: specs, box: box}, nil
}

// absDir returns the resolved path of an existing absolute directory.
func absDir(p string) (string, error) {
	if !filepath.IsAbs(p) || strings.ContainsRune(p, 0) {
		return "", ErrConfig
	}
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", ErrConfig
	}
	if fi, err := os.Stat(r); err != nil || !fi.IsDir() {
		return "", ErrConfig
	}
	return r, nil
}

// Has reports whether a tool has a spec.
func (r *Runner) Has(name string) bool { _, ok := r.specs[name]; return ok }

// Run implements toolgate.Runner.
func (r *Runner) Run(ctx context.Context, t toolgate.Tool, args []string) (toolgate.Output, error) {
	s, ok := r.specs[t.Name]
	if !ok {
		return toolgate.Output{}, ErrConfig
	}
	path, argv := r.box.wrap(s, append(append([]string(nil), s.Args...), args...), t.Network)
	cmd := exec.Command(path, argv...) // no shell, no PATH lookup (the path is absolute)
	cmd.Env, cmd.Dir = s.Env, s.Dir
	res, err := adapter.RunContained(ctx, cmd, t.Output)
	return toolgate.Output{Data: res.Output, Truncated: res.Truncated, Exit: res.Exit}, err
}
