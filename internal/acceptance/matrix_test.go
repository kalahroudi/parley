// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// The attack matrix (specs/parley-mvp/attack-matrix.md) maps every attack in the
// plan to the test that proves it is rejected or detected. This test keeps the
// document honest: it fails for a row whose test or subtest does not exist, a
// plan item that has no row, a pending row that is not a real pending test, and
// an attack test in the malicious-gateway files that no row names.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type matrixRow struct{ id, item, attack, outcome, test, sub string }

func readMatrix(text string) (rows []matrixRow, problems []string) {
	ids := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		if !regexp.MustCompile(`^\| A\d+ \|`).MatchString(line) {
			continue
		}
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		if len(cells) != 6 {
			problems = append(problems, "row has "+strconv.Itoa(len(cells))+" columns, want 6: "+line)
			continue
		}
		r := matrixRow{cells[0], cells[1], cells[2], cells[3], cells[4], cells[5]}
		if ids[r.id] {
			problems = append(problems, "duplicate row id "+r.id)
		}
		ids[r.id] = true
		rows = append(rows, r)
	}
	return rows, problems
}

// testFuncs maps each Test function in the package's test files to the string
// literals passed to t.Run inside it, and to the first argument literal of any
// pending(...) call.
type testFunc struct {
	file     string
	subtests map[string]bool
	pending  string
}

func sourceTests(t *testing.T) map[string]testFunc {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*_test.go")
	if err != nil || len(files) == 0 {
		t.Fatal("no test files", err)
	}
	out := map[string]testFunc{}
	for _, name := range files {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || fn.Body == nil {
				continue
			}
			tf := testFunc{file: name, subtests: map[string]bool{}}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok || len(c.Args) == 0 {
					return true
				}
				switch fun := c.Fun.(type) {
				case *ast.SelectorExpr:
					if fun.Sel.Name == "Run" {
						if lit, ok := c.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							s, _ := strconv.Unquote(lit.Value)
							tf.subtests[s] = true
						}
					}
				case *ast.Ident:
					if fun.Name == "pending" && len(c.Args) >= 2 {
						if lit, ok := c.Args[1].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							tf.pending, _ = strconv.Unquote(lit.Value)
						}
					}
				}
				return true
			})
			out[fn.Name.Name] = tf
		}
	}
	return out
}

// Every plan item the matrix must cover, with a phrase that must still be in
// plan.md (so changing the plan makes this test ask for a matrix update).
var planItems = []struct{ item, phrase string }{
	{"substitute keys", "substitutes keys"},
	{"replay", "replays"},
	{"reorder", "reorders"},
	{"swap replies", "swaps replies"},
	{"drop cancel", "drops cancel messages"},
	{"withheld prekeys", "withholds and reuses prekeys"},
	{"reused prekeys", "withholds and reuses prekeys"},
	{"junk frames", "junk frames cannot burn keys"},
	{"crash between open and ack", "a crash between open and acknowledgment"},
	{"crash between erase and execute", "and between erase and execute"},
	{"prekey expires while waiting", "a prekey expiring while the sender waits is refused"},
	{"redelivered frame", "a redelivered frame is dropped"},
	{"prekey flood, device", "a prekey request flood is rate-limited"},
	{"prekey flood, gateway", "a prekey request flood is rate-limited"},
	{"follow-up chain", "a five-message follow-up chain erases each key"},
	{"late reply after CANCEL", "a late reply after CANCEL is rejected"},
	{"disk clone", "a disk clone or restored backup holds no usable keys"},
	{"core dump and swap", "core-dump and swap scans find no key bytes"},
}

func TestAttackMatrix(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", "specs", "parley-mvp", p))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	rows, problems := readMatrix(read("attack-matrix.md"))
	for _, p := range problems {
		t.Error(p)
	}
	plan := read("plan.md")
	tests := sourceTests(t)
	if len(rows) < len(planItems) {
		t.Fatalf("only %d rows", len(rows))
	}

	named := map[string]bool{}
	items := map[string]bool{}
	for _, r := range rows {
		items[r.item] = true
		named[r.test] = true
		for name, v := range map[string]string{"plan item": r.item, "attack": r.attack, "outcome": r.outcome, "test": r.test, "subtest": r.sub} {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: empty %s", r.id, name)
			}
		}
		tf, ok := tests[r.test]
		if !ok {
			t.Errorf("%s: test %s does not exist in internal/acceptance", r.id, r.test)
			continue
		}
		if r.sub != "-" && !tf.subtests[r.sub] {
			t.Errorf("%s: %s has no subtest %q", r.id, r.test, r.sub)
		}
		switch task, isPending := strings.CutPrefix(r.outcome, "pending "); {
		case isPending:
			if !strings.HasPrefix(r.test, "TestPending_") || tf.pending != task {
				t.Errorf("%s: outcome %q needs a TestPending_ test that calls pending(t, %q, ...); %s calls it with %q", r.id, r.outcome, task, r.test, tf.pending)
			}
		case r.outcome != "rejected" && r.outcome != "detected" && r.outcome != "control":
			t.Errorf("%s: outcome %q is not rejected, detected, control or pending Txxx", r.id, r.outcome)
		case strings.HasPrefix(r.test, "TestPending_") || tf.pending != "":
			t.Errorf("%s: claims %s but the test only skips", r.id, r.outcome)
		}
	}

	for _, p := range planItems {
		if !strings.Contains(plan, p.phrase) {
			t.Errorf("plan.md no longer says %q: update the matrix and this list", p.phrase)
		}
		if !items[p.item] {
			t.Errorf("plan item %q has no row in attack-matrix.md", p.item)
		}
	}

	// The other way round: an attack test with no row is an unmapped attack.
	for name, tf := range tests {
		if (tf.file == "malgw_attacks_test.go" || tf.file == "malgw_frames_test.go" || tf.file == "spike3_prekeys_test.go") &&
			name != "TestTaskTicked" && !named[name] {
			t.Errorf("%s (%s) is in no row of attack-matrix.md", name, tf.file)
		}
	}
}

func TestAttackMatrixCheckerCatchesGaps(t *testing.T) {
	rows, problems := readMatrix("| A1 | x | y | rejected | TestReplay | - |\n| A1 | x | y | rejected | TestReplay | - |\n| A2 | short |\n")
	if len(rows) != 2 || len(problems) != 2 {
		t.Fatalf("rows %v, problems %v", rows, problems)
	}
	tests := sourceTests(t)
	if _, ok := tests["TestNoSuchAttack"]; ok {
		t.Fatal("phantom test found")
	}
	if tests["TestReplay"].subtests["no such subtest"] || !tests["TestReplay"].subtests["a task delivered twice runs once"] {
		t.Fatal("subtests not read from source")
	}
	if tests["TestPending_GatewayRelaysPrekeyRequestsThroughTheLimiter"].pending != "T412" {
		t.Fatal("pending task not read from source")
	}
}
