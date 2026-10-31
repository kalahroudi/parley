// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package logx

// Build test: fails if code anywhere in the repository could log a payload
// field. Run by `go test ./...` (and so by `make test` and CI on every OS).
//
// The scanner is deliberately fail-closed. It cannot prove a value is not
// task content, so it rejects anything it cannot show is safe:
//   - logx field constructors must be called directly, with a constant key
//     from Keys, and a value that does not mention a payload name, directly
//     or through a local variable that was assigned from one (taint);
//   - logx.Msg and field keys must be compile-time string constants;
//   - only the documented logx API may be used, so Keys and States cannot be
//     edited at run time and constructors cannot be aliased;
//   - other logging packages, fmt/print/os.Stderr writes and console.* that
//     touch a payload name are rejected;
//   - a deliberate exception needs `//logx:allow <reason>` on the same or the
//     previous line, which makes it visible in review.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// logxPath is the import path of this package.
const logxPath = "github.com/kalahroudi/parley/internal/logx"

// payloadNames are field names that carry task content. They must never be
// logged, so they are rejected even if someone adds them to Keys.
var payloadNames = map[string]struct{}{
	"input": {}, "inputs": {}, "result": {}, "results": {}, "status_text": {},
	"question": {}, "error": {}, "err": {}, "errors": {}, "file": {},
	"filename": {}, "file_name": {}, "text": {}, "payload": {}, "content": {},
	"body": {}, "plaintext": {}, "prompt": {}, "message": {}, "parts": {},
	"inner": {}, "ciphertext": {}, "secret": {}, "key": {}, "token": {},
}

// bannedImports are logging packages that bypass logx. A path matches if it
// equals an entry or is below it.
var bannedImports = []string{
	"log", "log/syslog", "golang.org/x/exp/slog",
	"go.uber.org/zap", "github.com/rs/zerolog", "github.com/sirupsen/logrus",
	"github.com/charmbracelet/log", "github.com/hashicorp/go-hclog",
	"github.com/go-kit/log", "github.com/apex/log", "github.com/golang/glog",
	"k8s.io/klog",
}

// logxAPI is every name outside this package may use.
var logxAPI = map[string]bool{
	"Logger": true, "New": true, "NewLevel": true, "Msg": true, "Field": true,
	"ID": true, "State": true, "Size": true, "Time": true, "Redacted": true,
}

// logxFields are the field constructors; they must be called, not aliased.
var logxFields = map[string]bool{"ID": true, "State": true, "Size": true, "Time": true}

func normName(s string) string { return strings.ReplaceAll(strings.ToLower(s), "_", "") }

var bannedNames = func() map[string]bool {
	m := map[string]bool{}
	for k := range payloadNames {
		m[normName(k)] = true
	}
	return m
}()

func bannedImport(p string) bool {
	if p == "log/slog" {
		return true
	}
	for _, b := range bannedImports {
		if p == b || strings.HasPrefix(p, b+"/") {
			return true
		}
	}
	return false
}

// importName is the identifier a file uses for an import.
func importName(imp *ast.ImportSpec) (p, name string) {
	p, _ = strconv.Unquote(imp.Path.Value)
	if imp.Name != nil {
		return p, imp.Name.Name
	}
	return p, path.Base(p)
}

// valueLeak returns the first identifier in e that is a payload name or a
// tainted local, or "". Package qualifiers are skipped, and so are the
// arguments of len and cap: a size is not content.
func valueLeak(e ast.Expr, tainted, pkgs map[string]bool) string {
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
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && pkgs[id.Name] {
				if bannedNames[normName(x.Sel.Name)] || tainted[x.Sel.Name] {
					found = x.Sel.Name
				}
				return false
			}
		case *ast.Ident:
			if bannedNames[normName(x.Name)] || tainted[x.Name] {
				found = x.Name
			}
		}
		return true
	})
	return found
}

// lhsNames returns the names an assignment target stores into.
func lhsNames(e ast.Expr) []string {
	switch x := e.(type) {
	case *ast.Ident:
		if x.Name != "_" {
			return []string{x.Name}
		}
	case *ast.SelectorExpr:
		return append(lhsNames(x.X), x.Sel.Name)
	case *ast.IndexExpr:
		return lhsNames(x.X)
	case *ast.StarExpr:
		return lhsNames(x.X)
	case *ast.ParenExpr:
		return lhsNames(x.X)
	}
	return nil
}

// taintedNames returns the names assigned from an expression that mentions a
// payload name or an already tainted name, to a fixed point. It is
// file-wide and by name, so it over-reports rather than misses.
func taintedNames(f *ast.File, pkgs map[string]bool) map[string]bool {
	t := map[string]bool{}
	changed := true
	mark := func(names []string) {
		for _, n := range names {
			if !t[n] {
				t[n] = true
				changed = true
			}
		}
	}
	leaks := func(es ...ast.Expr) bool {
		for _, e := range es {
			if valueLeak(e, t, pkgs) != "" {
				return true
			}
		}
		return false
	}
	for changed {
		changed = false
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if leaks(x.Rhs...) {
					for _, l := range x.Lhs {
						mark(lhsNames(l))
					}
				}
			case *ast.ValueSpec:
				if leaks(x.Values...) {
					for _, id := range x.Names {
						mark(lhsNames(id))
					}
				}
			case *ast.RangeStmt:
				if leaks(x.X) {
					for _, e := range []ast.Expr{x.Key, x.Value} {
						if e != nil {
							mark(lhsNames(e))
						}
					}
				}
			}
			return true
		})
	}
	return t
}

// fileConsts returns the file's string constants by name.
func fileConsts(f *ast.File) map[string]string {
	m := map[string]string{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			vs := s.(*ast.ValueSpec)
			if len(vs.Names) != len(vs.Values) {
				continue
			}
			for i, nm := range vs.Names {
				if v, ok := constString(vs.Values[i], m); ok {
					m[nm.Name] = v
				}
			}
		}
	}
	return m
}

// constString evaluates a string literal, a file constant, or a + of those.
func constString(e ast.Expr, consts map[string]string) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			s, err := strconv.Unquote(x.Value)
			return s, err == nil
		}
	case *ast.Ident:
		s, ok := consts[x.Name]
		return s, ok
	case *ast.ParenExpr:
		return constString(x.X, consts)
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			a, ok1 := constString(x.X, consts)
			b, ok2 := constString(x.Y, consts)
			return a + b, ok1 && ok2
		}
	}
	return "", false
}

// isStd reports whether e is os.Stderr or os.Stdout.
func isStd(e ast.Expr, osName string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == osName && (s.Sel.Name == "Stderr" || s.Sel.Name == "Stdout")
}

// scan returns violations in one Go source file. inLogx exempts the logx
// package itself from the import ban.
func scan(name string, src []byte, inLogx bool) []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		return []string{name + ": " + err.Error()}
	}
	var out []string
	allowLines := map[int]bool{}
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			text := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(c.Text, "//"), "/*"))
			rest, ok := strings.CutPrefix(text, "logx:allow")
			if !ok {
				continue
			}
			line := fset.Position(c.Pos()).Line
			if strings.TrimSpace(strings.TrimSuffix(rest, "*/")) == "" {
				out = append(out, fset.Position(c.Pos()).String()+": logx:allow needs a reason")
				continue
			}
			allowLines[line], allowLines[line+1] = true, true
		}
	}
	bad := func(p token.Pos, msg string) {
		pos := fset.Position(p)
		if allowLines[pos.Line] {
			return
		}
		out = append(out, pos.String()+": "+msg)
	}

	logxName, fmtName, osName, ioName := "", "", "", ""
	pkgs := map[string]bool{}
	for _, imp := range f.Imports {
		p, n := importName(imp)
		if n != "_" && n != "." {
			pkgs[n] = true
		}
		if bannedImport(p) && !inLogx {
			bad(imp.Pos(), "imports "+p+"; log through internal/logx")
		}
		switch p {
		case "fmt":
			fmtName = n
		case "os":
			osName = n
		case "io":
			ioName = n
		case logxPath:
			switch n {
			case ".":
				bad(imp.Pos(), "dot-import of logx hides calls from the scan")
			case "_":
			default:
				logxName = n
			}
		}
	}

	tainted := taintedNames(f, pkgs)
	consts := fileConsts(f)

	// Selectors that are the function of a call.
	called := map[*ast.SelectorExpr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if s, ok := c.Fun.(*ast.SelectorExpr); ok {
				called[s] = true
			}
		}
		return true
	})

	// checkArgs flags payload names in the arguments of a print-like call.
	checkArgs := func(call *ast.CallExpr, from int, what string) {
		for _, a := range call.Args[min(from, len(call.Args)):] {
			if v := valueLeak(a, tainted, pkgs); v != "" {
				bad(call.Pos(), what+" writes payload field "+strconv.Quote(v)+"; log through internal/logx")
			}
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			if !ok || logxName == "" || id.Name != logxName {
				return true
			}
			if !logxAPI[x.Sel.Name] {
				bad(x.Pos(), "logx."+x.Sel.Name+" is not part of the logging API")
			} else if logxFields[x.Sel.Name] && !called[x] {
				bad(x.Pos(), "logx."+x.Sel.Name+" must be called directly, not aliased")
			}
		case *ast.CallExpr:
			switch fn := x.Fun.(type) {
			case *ast.Ident:
				if (fn.Name == "print" || fn.Name == "println") && fn.Obj == nil {
					checkArgs(x, 0, fn.Name)
				}
			case *ast.SelectorExpr:
				recv, _ := fn.X.(*ast.Ident)
				switch {
				case recv != nil && fmtName != "" && recv.Name == fmtName && strings.HasPrefix(fn.Sel.Name, "Print"):
					checkArgs(x, 0, "fmt."+fn.Sel.Name)
				case recv != nil && fmtName != "" && recv.Name == fmtName && strings.HasPrefix(fn.Sel.Name, "Fprint") &&
					len(x.Args) > 0 && osName != "" && isStd(x.Args[0], osName):
					checkArgs(x, 1, "fmt."+fn.Sel.Name)
				case recv != nil && ioName != "" && recv.Name == ioName && fn.Sel.Name == "WriteString" &&
					len(x.Args) > 0 && osName != "" && isStd(x.Args[0], osName):
					checkArgs(x, 1, "io.WriteString")
				case osName != "" && isStd(fn.X, osName):
					checkArgs(x, 0, "os.Std stream write")
				}
				if recv == nil || logxName == "" || recv.Name != logxName {
					return true
				}
				switch fn.Sel.Name {
				case "ID", "State", "Size", "Time":
					k, ok := "", false
					if len(x.Args) > 0 {
						k, ok = constString(x.Args[0], consts)
					}
					switch {
					case !ok:
						bad(x.Pos(), "logx."+fn.Sel.Name+" key must be a constant string")
					case !Keys[k]:
						bad(x.Pos(), "logx key "+strconv.Quote(k)+" is not allowlisted")
					}
					if len(x.Args) > 1 {
						if v := valueLeak(x.Args[1], tainted, pkgs); v != "" {
							bad(x.Pos(), "logx."+fn.Sel.Name+" value references payload field "+strconv.Quote(v))
						}
						if fn.Sel.Name == "State" {
							if v, ok := constString(x.Args[1], consts); ok && !States[v] {
								bad(x.Pos(), "logx.State value "+strconv.Quote(v)+" is not a state code")
							}
						}
					}
				case "Msg":
					if len(x.Args) != 1 {
						bad(x.Pos(), "logx.Msg takes one argument")
					} else if _, ok := constString(x.Args[0], consts); !ok {
						bad(x.Pos(), "logx.Msg built from a non-constant")
					}
				}
			}
		}
		return true
	})
	return out
}

var (
	consoleRe  = regexp.MustCompile(`\bconsole\b`)
	tsAllowRe  = regexp.MustCompile(`logx:allow\s+\S`)
	tsBlockRe  = regexp.MustCompile(`(?s)/\*.*?\*/`)
	tsLineCmRe = regexp.MustCompile(`//[^\n]*`)
)

// scanTS returns violations in one TypeScript or JavaScript source file:
// any use of the console object, which writes to the Worker log.
func scanTS(name string, src []byte) []string {
	text := string(src)
	allow := map[int]bool{}
	for _, m := range tsLineCmRe.FindAllStringIndex(text, -1) {
		if tsAllowRe.MatchString(text[m[0]:m[1]]) {
			l := strings.Count(text[:m[0]], "\n") + 1
			allow[l], allow[l+1] = true, true
		}
	}
	// Blank comments out but keep line numbers.
	blank := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r == '\n' {
				return r
			}
			return ' '
		}, s)
	}
	code := tsBlockRe.ReplaceAllStringFunc(text, blank)
	code = tsLineCmRe.ReplaceAllStringFunc(code, blank)
	var out []string
	for i, line := range strings.Split(code, "\n") {
		if consoleRe.MatchString(line) && !allow[i+1] {
			out = append(out, name+":"+strconv.Itoa(i+1)+": uses console; log through the logging wrapper")
		}
	}
	return out
}

// moduleRoot is the repository root relative to this package.
var moduleRoot = filepath.Join("..", "..")

func TestNoPayloadFieldReachesALog(t *testing.T) {
	n := 0
	err := filepath.WalkDir(moduleRoot, func(p string, d fs.DirEntry, err error) error {
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
		rel, _ := filepath.Rel(moduleRoot, p)
		top := strings.Split(filepath.ToSlash(rel), "/")[0]
		isGo := strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go")
		ext := filepath.Ext(p)
		isTS := (top == "gateway" || top == "admin") && !strings.Contains(d.Name(), ".test.") &&
			(ext == ".ts" || ext == ".tsx" || ext == ".js" || ext == ".mjs" || ext == ".cjs")
		if !isGo && !isTS {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		n++
		var vs []string
		if isGo {
			inLogx := filepath.Clean(filepath.Dir(p)) == filepath.Join(moduleRoot, "internal", "logx")
			vs = scan(p, src, inLogx)
		} else {
			vs = scanTS(p, src)
		}
		for _, v := range vs {
			t.Error(v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("scanned no source files")
	}
}

// The scanner keys on logxPath; if the module is renamed it would silently
// skip every file.
func TestLogxPathMatchesModule(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if m, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			if got := strings.TrimSpace(m) + "/internal/logx"; got != logxPath {
				t.Fatalf("logxPath = %q, go.mod says %q", logxPath, got)
			}
			return
		}
	}
	t.Fatal("no module line in go.mod")
}
