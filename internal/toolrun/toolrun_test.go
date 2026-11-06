// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package toolrun_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/toolgate"
	"github.com/kalahroudi/parley/internal/toolrun"
)

func self(t testing.TB) string {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// spec runs this test binary as the tool, in mode, in a fresh jail.
func spec(t testing.TB, mode string, extra ...string) toolrun.Spec {
	return toolrun.Spec{Command: self(t), Dir: t.TempDir(), Env: append([]string{helperEnv + "=" + mode}, extra...)}
}

func TestNewRefusesBadTools(t *testing.T) {
	ok := spec(t, "args")
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o600)
	for name, s := range map[string]toolrun.Spec{
		"relative command": {Command: "tool", Dir: ok.Dir},
		"empty command":    {Dir: ok.Dir},
		"NUL command":      {Command: ok.Command + "\x00", Dir: ok.Dir},
		"no jail":          {Command: ok.Command},
		"relative jail":    {Command: ok.Command, Dir: "jail"},
		"missing jail":     {Command: ok.Command, Dir: filepath.Join(ok.Dir, "nope")},
		"jail is a file":   {Command: ok.Command, Dir: file},
		"NUL jail":         {Command: ok.Command, Dir: ok.Dir + "\x00"},
		"NUL arg":          {Command: ok.Command, Dir: ok.Dir, Args: []string{"a\x00"}},
		"env no =":         {Command: ok.Command, Dir: ok.Dir, Env: []string{"A"}},
		"env empty name":   {Command: ok.Command, Dir: ok.Dir, Env: []string{"=A"}},
		"env NUL":          {Command: ok.Command, Dir: ok.Dir, Env: []string{"A=b\x00"}},
	} {
		if _, err := toolrun.NewUnsandboxed(map[string]toolrun.Spec{"t": s}); !errors.Is(err, toolrun.ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// plainRunner runs t's tool "t" without a sandbox, on every operating system.
func plainRunner(t *testing.T, s toolrun.Spec) *toolrun.Runner {
	t.Helper()
	r, err := toolrun.NewUnsandboxed(map[string]toolrun.Spec{"t": s})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// sandboxRunner builds the real Runner, or skips where the sandbox cannot run, except in CI, where it must.
func sandboxRunner(t *testing.T, s toolrun.Spec, hide ...string) *toolrun.Runner {
	t.Helper()
	r, err := toolrun.New(toolrun.Config{Specs: map[string]toolrun.Spec{"t": s}, Hide: hide})
	if errors.Is(err, toolrun.ErrNoSandbox) {
		if os.Getenv("CI") != "" && (runtime.GOOS == "linux" || runtime.GOOS == "darwin") {
			t.Fatalf("CI must have the sandbox for %s: %v", runtime.GOOS, err)
		}
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// each runs f with the runner without a sandbox, and with the real one where it exists.
func each(t *testing.T, s toolrun.Spec, f func(t *testing.T, r *toolrun.Runner)) {
	t.Run("plain", func(t *testing.T) { f(t, plainRunner(t, s)) })
	t.Run("sandbox", func(t *testing.T) { f(t, sandboxRunner(t, s)) })
}

func TestRunOfAnUnknownToolFails(t *testing.T) {
	r := plainRunner(t, spec(t, "args"))
	if !r.Has("t") || r.Has("u") {
		t.Fatal("Has")
	}
	if _, err := r.Run(context.Background(), toolgate.Tool{Name: "u"}, nil); !errors.Is(err, toolrun.ErrConfig) {
		t.Fatalf("%v", err)
	}
}

func run(t *testing.T, r *toolrun.Runner, network bool, args ...string) toolgate.Output {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := r.Run(ctx, toolgate.Tool{Name: "t", Network: network, Output: 1 << 16}, args)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestToolRunsDirectlyWithTheApprovedArgumentsAndNoInheritedEnvironment(t *testing.T) {
	t.Setenv("PARLEY_SECRET", "SECRET-CANARY")
	s := spec(t, "args", "KEEP=1")
	s.Args = []string{"-fixed", "a b"}
	each(t, s, func(t *testing.T, r *toolrun.Runner) {
		hostile := []string{"; touch pwned", "$(touch pwned)", "`id`", "a b", "*", "--", ""}
		out := run(t, r, false, hostile...)
		want := "-fixed|a b|; touch pwned|$(touch pwned)|`id`|a b|*|--|;2" // the helper variable and KEEP
		if string(out.Data) != want || out.Exit != 0 || out.Truncated {
			t.Fatalf("%q exit %d", out.Data, out.Exit)
		}
		if _, err := os.Stat(filepath.Join(s.Dir, "pwned")); err == nil {
			t.Fatal("an argument was run by a shell")
		}
	})
}

func TestToolRunsInItsJail(t *testing.T) {
	s := spec(t, "cwd")
	each(t, s, func(t *testing.T, r *toolrun.Runner) {
		if out := run(t, r, false); !sameDir(t, string(out.Data), s.Dir) {
			t.Fatalf("working directory %q, jail %q", out.Data, s.Dir)
		}
	})
}

func sameDir(t *testing.T, a, b string) bool {
	t.Helper()
	ra, _ := filepath.EvalSymlinks(a)
	rb, _ := filepath.EvalSymlinks(b)
	return ra != "" && ra == rb
}

func TestToolWritesOnlyInItsJail(t *testing.T) {
	w := spec(t, "write")
	r := sandboxRunner(t, w)
	if out := run(t, r, false, filepath.Join(w.Dir, "inside")); string(out.Data) != "ok" {
		t.Fatalf("inside the jail: %q", out.Data)
	}
	if _, err := os.Stat(filepath.Join(w.Dir, "inside")); err != nil {
		t.Fatal("the file in the jail was not written")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if out := run(t, r, false, outside); string(out.Data) != "denied" {
		t.Fatalf("outside the jail: %q", out.Data)
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("the tool wrote outside its jail")
	}
	if out := run(t, r, true, outside); string(out.Data) != "denied" { // the network does not open the file system
		t.Fatalf("outside the jail with the network: %q", out.Data)
	}
	// Control: without the sandbox the same write works, so the denial above is the sandbox's.
	if out := run(t, plainRunner(t, w), false, outside); string(out.Data) != "ok" {
		t.Fatalf("control: %q", out.Data)
	}
}

func TestToolHasNoNetworkUnlessDeclared(t *testing.T) {
	ln := listen(t)
	r := sandboxRunner(t, spec(t, "dial"))
	if out := run(t, r, false, "tcp", ln); string(out.Data) != "denied" {
		t.Fatalf("without the network: %q", out.Data)
	}
	if out := run(t, r, true, "tcp", ln); string(out.Data) != "ok" {
		t.Fatalf("with the network: %q", out.Data)
	}
}

func TestToolCannotReachTheDaemonsDirectoryOrSocket(t *testing.T) {
	hidden, err := os.MkdirTemp("/tmp", "pt") // short: a Unix-domain socket path is limited to about 100 bytes
	if err != nil {
		t.Skip("no /tmp")
	}
	t.Cleanup(func() { os.RemoveAll(hidden) })
	secret := filepath.Join(hidden, "key")
	os.WriteFile(secret, []byte("KEY"), 0o600)
	sock := unixListen(t, hidden)
	for _, network := range []bool{false, true} {
		if out := run(t, sandboxRunner(t, spec(t, "read"), hidden), network, secret); string(out.Data) != "denied" {
			t.Errorf("network=%v: read the daemon's directory: %q", network, out.Data)
		}
		if out := run(t, sandboxRunner(t, spec(t, "dial"), hidden), network, "unix", sock); string(out.Data) != "denied" {
			t.Errorf("network=%v: reached the daemon's socket: %q", network, out.Data)
		}
	}
	// Control: without hiding, the same read and connection work, so the denials above are the sandbox's.
	if out := run(t, plainRunner(t, spec(t, "read")), false, secret); string(out.Data) != "ok:KEY" {
		t.Fatalf("control read: %q", out.Data)
	}
	if out := run(t, plainRunner(t, spec(t, "dial")), false, "unix", sock); string(out.Data) != "ok" {
		t.Fatalf("control dial: %q", out.Data)
	}
}

func TestToolIsKilledWhenItsTimeRunsOut(t *testing.T) {
	each(t, spec(t, "sleep"), func(t *testing.T, r *toolrun.Runner) {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := r.Run(ctx, toolgate.Tool{Name: "t", Output: 100}, nil)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 20*time.Second {
			t.Fatalf("%v after %v", err, time.Since(start))
		}
	})
}

func TestToolOutputAndExitAreBounded(t *testing.T) {
	each(t, spec(t, "big"), func(t *testing.T, r *toolrun.Runner) {
		out, err := r.Run(context.Background(), toolgate.Tool{Name: "t", Output: 1000}, nil)
		if err != nil || len(out.Data) != 1000 || !out.Truncated {
			t.Fatalf("%d bytes, truncated %v, %v", len(out.Data), out.Truncated, err)
		}
	})
	each(t, spec(t, "exit"), func(t *testing.T, r *toolrun.Runner) {
		if out := run(t, r, false, "7"); out.Exit != 7 {
			t.Fatalf("exit %d", out.Exit)
		}
	})
}
