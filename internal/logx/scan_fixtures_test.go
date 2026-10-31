// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package logx

import (
	"strings"
	"testing"
)

// goSrc wraps a function body in a file that imports what the cases use.
func goSrc(body string) string {
	return `package x
import (
	"fmt"
	"io"
	"os"
	"errors"
	"` + logxPath + `"
)
const keyTask = "task"
const keyBody = "body"
const stBad = "boom"
func f(l *logx.Logger, task, s string, res R, in R) {
	_, _, _, _ = fmt.Sprint, io.EOF, os.Args, errors.New
` + body + `
}`
}

// Each case lists a substring every violation message set must contain, or ""
// for a snippet that must be clean.
var goCases = []struct {
	name, body string
	n          int
	want       string
}{
	{"clean", `l.Info("ok", logx.ID("task", task), logx.State("state", "TASK_STATE_FAILED"), logx.Size("size", int64(len(in.Input))))`, 0, ""},
	{"const key", `l.Info("ok", logx.ID(keyTask, task))`, 0, ""},
	{"const key not allowlisted", `l.Info("x", logx.ID(keyBody, task))`, 1, "not allowlisted"},
	{"key not allowlisted", `l.Info("x", logx.ID("input", task))`, 1, "not allowlisted"},
	{"key variable", `l.Info("x", logx.ID(s, task))`, 1, "constant string"},
	{"value field", `l.Info("x", logx.ID("task", res.Text))`, 1, "payload field"},
	{"value ident", `l.Info("x", logx.ID("task", body))`, 1, "payload field"},
	{"value nested call", `l.Info("x", logx.ID("task", strings.TrimSpace(res.Text)))`, 1, "payload field"},
	{"value in size", `l.Info("x", logx.Size("size", int64(res.Count+len(in.Input)+score(in.Input))))`, 1, "payload field"},
	{"taint one hop", "x := res.Text\nl.Info(\"x\", logx.ID(\"task\", x))", 1, "\"x\""},
	{"taint two hops", "x := res.Text\ny := x\nl.Info(\"x\", logx.ID(\"task\", y))", 1, "\"y\""},
	{"taint var decl", "var x = in.Question\nl.Info(\"x\", logx.ID(\"task\", x))", 1, "\"x\""},
	{"taint multi assign", "a, b := split(res.Text)\nl.Info(\"x\", logx.ID(\"task\", b))", 1, "\"b\""},
	{"taint range", "for _, v := range res.Parts {\nl.Info(\"x\", logx.ID(\"task\", v))\n}", 1, "\"v\""},
	{"taint field store", "var o O\no.v = res.Text\nl.Info(\"x\", logx.ID(\"task\", o.v))", 1, "payload field"},
	{"len of payload is a size", "n := len(res.Text)\nl.Info(\"x\", logx.Size(\"size\", int64(n)))", 0, ""},
	{"package qualifier is not payload", `l.Info("x", logx.ID("task", errors.Unwrap2(task)))`, 0, ""},
	{"state literal", `l.Info("x", logx.State("state", "boom"))`, 1, "not a state code"},
	{"state const", `l.Info("x", logx.State("state", stBad))`, 1, "not a state code"},
	{"msg variable", `l.Info(logx.Msg(s))`, 1, "non-constant"},
	{"msg concat of constants", `l.Info(logx.Msg("a" + "b"))`, 0, ""},
	{"msg concat with variable", `l.Info(logx.Msg("a" + s))`, 1, "non-constant"},
	{"alias constructor", `g := logx.ID; l.Info("x", g("input", task))`, 1, "called directly"},
	{"alias as argument", `use(logx.State)`, 1, "called directly"},
	{"mutate keys", `logx.Keys["body"] = true`, 1, "not part of the logging API"},
	{"mutate states", `logx.States[s] = true`, 1, "not part of the logging API"},
	{"fmt.Println payload", `fmt.Println(res.Text)`, 1, "fmt.Println"},
	{"fmt.Printf tainted", "x := in.Input\nfmt.Printf(\"%s\", x)", 1, "fmt.Printf"},
	{"fmt.Fprintln stderr err", `fmt.Fprintln(os.Stderr, "run:", err)`, 1, "fmt.Fprintln"},
	{"fmt.Fprintf stdout payload", `fmt.Fprintf(os.Stdout, "%s", res.Result)`, 1, "fmt.Fprintf"},
	{"fmt.Fprintf buffer is not a log", `fmt.Fprintf(&b, "%s", res.Text)`, 0, ""},
	{"fmt.Println constants", `fmt.Println("parleyd", version)`, 0, ""},
	{"println builtin", `println(in.Input)`, 1, "println"},
	{"stderr write", `os.Stderr.WriteString(res.Text)`, 1, "os.Std"},
	{"stdout write", `os.Stdout.Write(res.Body)`, 1, "os.Std"},
	{"io.WriteString stderr", `io.WriteString(os.Stderr, res.Text)`, 1, "io.WriteString"},
	{"allow with reason same line", `fmt.Fprintln(os.Stderr, "run:", err) //logx:allow startup error, no task exists yet`, 0, ""},
	{"allow with reason previous line", "//logx:allow startup error, no task exists yet\nfmt.Fprintln(os.Stderr, \"run:\", err)", 0, ""},
	{"allow without reason", "//logx:allow\nfmt.Fprintln(os.Stderr, \"run:\", err)", 2, "needs a reason"},
	{"allow does not reach two lines down", "//logx:allow startup error\n_ = 1\nfmt.Fprintln(os.Stderr, \"run:\", err)", 1, "fmt.Fprintln"},
}

func TestScanGoCases(t *testing.T) {
	for _, c := range goCases {
		t.Run(c.name, func(t *testing.T) {
			got := scan("x.go", []byte(goSrc(c.body)), false)
			if len(got) != c.n {
				t.Fatalf("want %d violations, got %d: %v", c.n, len(got), got)
			}
			if c.want != "" && !strings.Contains(strings.Join(got, "\n"), c.want) {
				t.Fatalf("want a violation containing %q: %v", c.want, got)
			}
		})
	}
}

func TestScanImports(t *testing.T) {
	banned := []string{
		"log", "log/slog", "log/syslog", "golang.org/x/exp/slog", "go.uber.org/zap",
		"go.uber.org/zap/zapcore", "github.com/rs/zerolog/log", "github.com/sirupsen/logrus",
		"github.com/hashicorp/go-hclog", "k8s.io/klog/v2", "github.com/go-kit/log",
		"github.com/apex/log", "github.com/golang/glog", "github.com/charmbracelet/log",
	}
	for _, p := range banned {
		src := "package x\nimport _ \"" + p + "\"\n"
		if v := scan("x.go", []byte(src), false); len(v) != 1 {
			t.Errorf("%s: want 1 violation, got %v", p, v)
		}
		if v := scan("x.go", []byte(src), true); len(v) != 0 {
			t.Errorf("%s: logx itself may import it, got %v", p, v)
		}
	}
	for _, p := range []string{"logger", "example.com/log", "go.uber.org/zapx", "github.com/me/log/slog2", "context"} {
		src := "package x\nimport _ \"" + p + "\"\n"
		if v := scan("x.go", []byte(src), false); len(v) != 0 {
			t.Errorf("%s must not be banned: %v", p, v)
		}
	}
}

func TestScanLogxImportForms(t *testing.T) {
	const alias = `package x
import lx "` + logxPath + `"
var _ = lx.Size("body", 1)
var _ = lx.Size("size", 1)
var _ = other.Foo("body")
var _ = fn()("x")`
	if v := scan("x.go", []byte(alias), false); len(v) != 1 {
		t.Fatalf("alias import not tracked: %v", v)
	}
	dot := "package x\nimport . \"" + logxPath + "\"\nvar _ = ID(\"body\", \"x\")\n"
	if v := scan("x.go", []byte(dot), false); len(v) != 1 || !strings.Contains(v[0], "dot-import") {
		t.Fatalf("dot-import must be rejected: %v", v)
	}
	if v := scan("x.go", []byte("package x\nfunc("), false); len(v) != 1 {
		t.Fatalf("parse error must be reported: %v", v)
	}
	// Using the logx types in signatures is fine.
	const types = `package x
import "` + logxPath + `"
func g(l *logx.Logger, m logx.Msg, f ...logx.Field) { l.Info(m, f...); _ = logx.Redacted; _ = logx.New(nil) }`
	if v := scan("x.go", []byte(types), false); len(v) != 0 {
		t.Fatalf("types and New are allowed: %v", v)
	}
}

var tsCases = []struct {
	name, src string
	n         int
}{
	{"log", "console.log(x)", 1},
	{"error", "  console.error(e)", 1},
	{"alias", "const c = console;", 1},
	{"destructure", "const { log } = console;", 1},
	{"bracket", "console['log'](x)", 1},
	{"line comment", "// console.log(x)\nexport {}", 0},
	{"block comment", "/* console.log(x)\n console.warn(y) */\nexport {}", 0},
	{"mid word", "const consoleish = 1; reconsole()", 0},
	{"allow same line", "console.log(x) // logx:allow boot banner", 0},
	{"allow previous line", "// logx:allow boot banner\nconsole.log(x)", 0},
	{"allow without reason", "// logx:allow\nconsole.log(x)", 1},
	{"line number kept", "/* a\nb */\nconsole.log(x)", 1},
}

func TestScanTSCases(t *testing.T) {
	for _, c := range tsCases {
		t.Run(c.name, func(t *testing.T) {
			if got := scanTS("x.ts", []byte(c.src)); len(got) != c.n {
				t.Fatalf("want %d violations, got %d: %v", c.n, len(got), got)
			}
		})
	}
	if got := scanTS("x.ts", []byte("/* a\nb */\nconsole.log(x)")); len(got) != 1 || !strings.Contains(got[0], "x.ts:3:") {
		t.Fatalf("want line 3, got %v", got)
	}
}
