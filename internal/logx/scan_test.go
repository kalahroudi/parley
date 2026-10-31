// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package logx

// Build test: fails if code anywhere in the module could log a payload field.
// Run by `go test ./...` (and so by `make test` and CI on every OS).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// payloadNames are field names that carry task content. They must never be
// logged, so they are rejected even if someone adds them to Keys.
var payloadNames = map[string]struct{}{
	"input": {}, "inputs": {}, "result": {}, "results": {}, "status_text": {},
	"question": {}, "error": {}, "err": {}, "errors": {}, "file": {},
	"filename": {}, "file_name": {}, "text": {}, "payload": {}, "content": {},
	"body": {}, "plaintext": {}, "prompt": {}, "message": {}, "parts": {},
	"inner": {}, "ciphertext": {}, "secret": {}, "key": {}, "token": {},
}

// bannedImports are logging packages that bypass logx.
var bannedImports = map[string]bool{
	"log": true, "log/slog": true, "log/syslog": true,
	"go.uber.org/zap": true, "github.com/rs/zerolog": true,
	"github.com/sirupsen/logrus": true, "github.com/charmbracelet/log": true,
}

// scan returns violations in one Go source file. inLogx exempts the logx
// package itself from the import ban.
func scan(name string, src []byte, inLogx bool) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return []string{name + ": " + err.Error()}
	}
	var out []string
	bad := func(p token.Pos, msg string) {
		out = append(out, fset.Position(p).String()+": "+msg)
	}
	logxName := ""
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if bannedImports[path] && !inLogx {
			bad(imp.Pos(), "imports "+path+"; log through internal/logx")
		}
		if path == "github.com/kalahroudi/parley/internal/logx" {
			logxName = "logx"
			if imp.Name != nil {
				logxName = imp.Name.Name
			}
		}
	}
	if logxName == "" {
		return out
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != logxName {
			return true
		}
		lit := func(i int) (string, bool) {
			if i >= len(call.Args) {
				return "", false
			}
			b, ok := call.Args[i].(*ast.BasicLit)
			if !ok || b.Kind != token.STRING {
				return "", false
			}
			s, _ := strconv.Unquote(b.Value)
			return s, true
		}
		switch sel.Sel.Name {
		case "ID", "State", "Size", "Time":
			k, ok := lit(0)
			switch {
			case !ok:
				bad(call.Pos(), "logx."+sel.Sel.Name+" key must be a string literal")
			case !Keys[k]:
				bad(call.Pos(), "logx key "+strconv.Quote(k)+" is not allowlisted")
			}
			if len(call.Args) > 1 {
				if name := valueLeak(call.Args[1]); name != "" {
					bad(call.Pos(), "logx."+sel.Sel.Name+" value references payload field "+strconv.Quote(name))
				}
			}
			if sel.Sel.Name == "State" {
				if v, ok := lit(1); ok && !States[v] {
					bad(call.Pos(), "logx.State value "+strconv.Quote(v)+" is not a state code")
				}
			}
		case "Msg":
			if _, ok := lit(0); !ok {
				bad(call.Pos(), "logx.Msg built from a non-constant")
			}
		}
		return true
	})
	return out
}

// valueLeak returns the first identifier or field in a logx value expression
// whose name is a payload name (case and underscores ignored), so
// logx.ID("task", res.Text) is caught even though safeID would accept the
// text. Arguments of len and cap are skipped: a size is not content.
func valueLeak(e ast.Expr) string {
	norm := func(s string) string {
		return strings.ReplaceAll(strings.ToLower(s), "_", "")
	}
	bannedNames := map[string]bool{}
	for k := range payloadNames {
		bannedNames[norm(k)] = true
	}
	found := ""
	ast.Inspect(e, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		switch x := n.(type) {
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && (id.Name == "len" || id.Name == "cap") {
				return false
			}
		case *ast.Ident:
			if bannedNames[norm(x.Name)] {
				found = x.Name
			}
		}
		return true
	})
	return found
}

func TestScanFlagsLeaks(t *testing.T) {
	const p = `package x
import ("log"; "github.com/kalahroudi/parley/internal/logx")
func f(l *logx.Logger, task, s string) {
	l.Info("ok", logx.ID("task", task), logx.State("state", "TASK_STATE_FAILED"))
	l.Info("leak", logx.ID("input", task))
	l.Info("leak", logx.ID(s, task))
	l.Info("leak", logx.State("state", "boom"))
	l.Info(logx.Msg(s))
	l.Info("leak", logx.ID("task", res.Text))
	l.Info("ok", logx.Size("size", int64(len(in.Input))))
	log.Println(s)
}`
	got := scan("x.go", []byte(p), false)
	if len(got) != 6 {
		t.Fatalf("want 6 violations, got %d: %v", len(got), got)
	}
	if v := scan("x.go", []byte(p), true); len(v) != 5 {
		t.Fatalf("logx package may import log: %v", v)
	}
	if v := scan("x.go", []byte("package x\nfunc("), false); len(v) != 1 {
		t.Fatalf("parse error must be reported: %v", v)
	}
	const alias = `package x
import lx "github.com/kalahroudi/parley/internal/logx"
var _ = lx.Size("body", 1)
var _ = lx.Size("size", 1)
var _ = other.Foo("body")
var _ = fn()("x")`
	if v := scan("x.go", []byte(alias), false); len(v) != 1 {
		t.Fatalf("alias import not tracked: %v", v)
	}
}

func TestNoPayloadFieldReachesALog(t *testing.T) {
	root := filepath.Join("..", "..")
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist", ".wrangler":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		n++
		inLogx := filepath.Clean(filepath.Dir(p)) == filepath.Join(root, "internal", "logx")
		for _, v := range scan(p, src, inLogx) {
			t.Error(v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("scanned no Go files")
	}
}
