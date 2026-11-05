// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Command covergate enforces the coverage tiers from a Go cover profile.
//
// Go reports statement coverage only, so the "line" gate here is statement
// coverage per package; branch coverage for Go code is checked by mutation
// testing (see "make mutation"). A statement or function can be excluded with a
// comment on the line directly above it:
//
//	//cover:ignore <reason>
//
// The reason is mandatory, every exclusion is listed in the output so review
// can sign it off, and tier 1 packages may not use any.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const marker = "//cover:ignore"

// Config maps a tier number to its gate and packages (module-relative paths).
type Config struct {
	Tiers map[string]Tier `json:"tiers"`
}

// Tier is one row of the plan's coverage policy.
type Tier struct {
	Line     float64  `json:"line"`
	Packages []string `json:"packages"`
}

type block struct {
	file               string
	startLine, endLine int
	stmts, count       int
}

type tally struct{ covered, total int }

func main() {
	profile := flag.String("profile", "cover.out", "Go cover profile")
	cfgPath := flag.String("config", "tests/coverage/tiers.json", "tier configuration")
	flag.Parse()
	os.Exit(run(*profile, *cfgPath, ".", os.Stdout, os.Stderr))
}

func run(profile, cfgPath, root string, out, errw io.Writer) int {
	var cfg Config
	if err := readJSON(cfgPath, &cfg); err != nil {
		fmt.Fprintln(errw, "covergate:", err)
		return 2
	}
	module, err := modulePath(filepath.Join(root, "go.mod"))
	if err != nil {
		fmt.Fprintln(errw, "covergate:", err)
		return 2
	}
	blocks, err := readProfile(profile, module)
	if err != nil {
		fmt.Fprintln(errw, "covergate:", err)
		return 2
	}
	byPkg := map[string][]block{}
	for _, b := range blocks {
		byPkg[path.Dir(b.file)] = append(byPkg[path.Dir(b.file)], b)
	}

	tierOf := map[string]string{}
	for name, t := range cfg.Tiers {
		for _, p := range t.Packages {
			tierOf[p] = name
		}
	}
	failed := false
	fail := func(format string, a ...any) {
		failed = true
		fmt.Fprintf(errw, "FAIL "+format+"\n", a...)
	}

	pkgs := make([]string, 0, len(byPkg))
	for p := range byPkg {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	var excluded []string
	for _, p := range pkgs {
		tier, ok := tierOf[p]
		if !ok {
			fail("%s has statements but is in no coverage tier (add it to %s)", p, cfgPath)
			continue
		}
		ign, err := ignores(root, byPkg[p])
		if err != nil {
			fmt.Fprintln(errw, "covergate:", err)
			return 2
		}
		var t tally
		var missed []block
		for _, b := range byPkg[p] {
			if ign.covers(b) {
				continue
			}
			t.total += b.stmts
			if b.count > 0 {
				t.covered += b.stmts
			} else {
				missed = append(missed, b)
			}
		}
		for _, e := range ign.list {
			excluded = append(excluded, fmt.Sprintf("tier %s  %s:%d  %s", tier, e.file, e.line, e.reason))
			if tier == "1" {
				fail("%s:%d: tier 1 allows no coverage exclusions", e.file, e.line)
			}
		}
		pct := 100.0
		if t.total > 0 {
			pct = 100 * float64(t.covered) / float64(t.total)
		}
		gate := cfg.Tiers[tier].Line
		status := "ok  "
		if pct < gate {
			status = "FAIL"
			failed = true
		}
		fmt.Fprintf(out, "%s tier %s  %-26s %6.1f%%  (gate %.0f%%, %d/%d statements)\n", status, tier, p, pct, gate, t.covered, t.total)
		if status == "FAIL" {
			// Which statements, so a gate that fails on one OS only (a profile is per run) names its line.
			sort.Slice(missed, func(i, j int) bool {
				if missed[i].file != missed[j].file {
					return missed[i].file < missed[j].file
				}
				return missed[i].startLine < missed[j].startLine
			})
			for _, b := range missed {
				fmt.Fprintf(out, "     not covered: %s:%d-%d (%d statements)\n", b.file, b.startLine, b.endLine, b.stmts)
			}
		}
	}
	// A configured package with no statements in the profile was renamed,
	// removed or left out of the test run; a silent pass would hide that.
	for p, tier := range tierOf {
		if _, ok := byPkg[p]; !ok {
			fail("tier %s package %s is not in the profile (renamed, removed, or not tested?)", tier, p)
		}
	}
	if len(excluded) > 0 {
		sort.Strings(excluded)
		fmt.Fprintln(out, "\nCoverage exclusions (each needs review sign-off):")
		for _, e := range excluded {
			fmt.Fprintln(out, "  "+e)
		}
	}
	if failed {
		return 1
	}
	return 0
}

func readJSON(p string, v any) error {
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	return nil
}

func modulePath(gomod string) (string, error) {
	data, err := os.ReadFile(gomod)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(data), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "module" {
			return f[1], nil
		}
	}
	return "", fmt.Errorf("%s: no module line", gomod)
}

// readProfile parses "file:startLine.col,endLine.col numStmts count" lines.
func readProfile(p, module string) ([]block, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var out []block
	for i, l := range strings.Split(string(data), "\n") {
		if l == "" || strings.HasPrefix(l, "mode:") {
			continue
		}
		b, ok := parseBlock(l, module)
		if !ok {
			return nil, fmt.Errorf("%s:%d: malformed profile line", p, i+1)
		}
		out = append(out, b)
	}
	return out, nil
}

func parseBlock(l, module string) (block, bool) {
	colon := strings.LastIndex(l, ":")
	f := strings.Fields(l[colon+1:])
	if colon < 0 || len(f) != 3 {
		return block{}, false
	}
	span := strings.SplitN(f[0], ",", 2)
	if len(span) != 2 {
		return block{}, false
	}
	start, e1 := strconv.Atoi(strings.SplitN(span[0], ".", 2)[0])
	end, e2 := strconv.Atoi(strings.SplitN(span[1], ".", 2)[0])
	stmts, e3 := strconv.Atoi(f[1])
	count, e4 := strconv.Atoi(f[2])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return block{}, false
	}
	return block{strings.TrimPrefix(l[:colon], module+"/"), start, end, stmts, count}, true
}

type exclusion struct {
	file               string
	line               int
	startLine, endLine int
	reason             string
}

type ignoreSet struct{ list []exclusion }

func (s ignoreSet) covers(b block) bool {
	for _, e := range s.list {
		if e.file == b.file && b.startLine >= e.startLine && b.endLine <= e.endLine {
			return true
		}
	}
	return false
}

// ignores finds the //cover:ignore comments in the files of blocks and resolves
// each to the statement or declaration that starts on the next line.
func ignores(root string, blocks []block) (ignoreSet, error) {
	files := map[string]bool{}
	for _, b := range blocks {
		files[b.file] = true
	}
	names := make([]string, 0, len(files))
	for f := range files {
		names = append(names, f)
	}
	sort.Strings(names)
	var set ignoreSet
	for _, name := range names {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(name)), nil, parser.ParseComments)
		if err != nil {
			return set, err
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if !strings.HasPrefix(c.Text, marker) {
					continue
				}
				line := fset.Position(c.Pos()).Line
				reason := strings.TrimSpace(strings.TrimPrefix(c.Text, marker))
				if reason == "" {
					return set, fmt.Errorf("%s:%d: %s needs a written reason", name, line, marker)
				}
				start, end := nextNode(fset, f, line+1)
				if start == 0 {
					return set, fmt.Errorf("%s:%d: %s is not followed by a statement or declaration", name, line, marker)
				}
				set.list = append(set.list, exclusion{name, line, start, end, reason})
			}
		}
	}
	return set, nil
}

// nextNode returns the line span of the outermost statement or declaration that
// starts on line, or 0 if there is none.
func nextNode(fset *token.FileSet, f *ast.File, line int) (int, int) {
	start, end := 0, 0
	ast.Inspect(f, func(n ast.Node) bool {
		switch n.(type) {
		case ast.Stmt, ast.Decl:
		default:
			return true
		}
		if start != 0 || fset.Position(n.Pos()).Line != line {
			return start == 0
		}
		start, end = line, fset.Position(n.End()).Line
		return false
	})
	return start, end
}
