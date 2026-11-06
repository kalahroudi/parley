// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package reviewer_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/pipeline"
	"github.com/kalahroudi/parley/internal/reviewer"
)

// Placeholders assembled at run time, so no key-shaped literal is in the source.
var (
	fakeKeyID = "AK" + "IA" + strings.Repeat("Z", 16)
	pemHeader = "-----" + "BEGIN " + "%s" + "PRIVATE" + " KEY-----"
	goodDiff  = goodDiffFor(fakeKeyID)
)

func goodDiffFor(id string) string {
	return "diff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -1,3 +1,6 @@\n package main\n+// TODO: later\n func f() {\n+\tfmt.Println(\"x\")\n+\tkey := \"" + id + "\"\n }\n"
}

func TestReviewFindsWhatItShouldWithLineNumbers(t *testing.T) {
	f, added, more := reviewer.Review([]byte(goodDiff))
	if added != 3 || more {
		t.Fatalf("added=%d more=%v", added, more)
	}
	want := []reviewer.Finding{
		{"main.go", 2, "unfinished work marker"},
		{"main.go", 4, "leftover debug output"},
		{"main.go", 5, "possible secret: cloud access key id"},
	}
	if len(f) != len(want) {
		t.Fatalf("findings = %+v", f)
	}
	for i := range want {
		if f[i] != want[i] {
			t.Errorf("finding %d = %+v, want %+v", i, f[i], want[i])
		}
	}
}

func rule(t *testing.T, line string) []reviewer.Finding {
	t.Helper()
	f, _, _ := reviewer.Review([]byte("+++ b/x\n@@ -0,0 +1 @@\n+" + line + "\n"))
	return f
}

func TestEachRule(t *testing.T) {
	for _, c := range []struct{ line, rule string }{
		{strings.Replace(pemHeader, "%s", "RSA ", 1), "possible secret: private key"},
		{strings.Replace(pemHeader, "%s", "", 1), "possible secret: private key"},
		{fakeKeyID, "possible secret: cloud access key id"},
		{`password = "hunter2hunter2"`, "possible secret: credential assigned a literal"},
		{`"api_key": "abcdefgh12345"`, "possible secret: credential assigned a literal"},
		{`token := "abcdefghijkl"`, "possible secret: credential assigned a literal"},
		{`token: 'abcdefghijkl'`, "possible secret: credential assigned a literal"},
		{"console.log(x)", "leftover debug output"},
		{"debugger;", "leftover debug output"},
		{"fmt.Printf(x)", "leftover debug output"},
		{"// FIXME", "unfinished work marker"},
		{"x := 1 ", "trailing whitespace"},
		{"x := 1\t", "trailing whitespace"},
	} {
		f := rule(t, c.line)
		if len(f) != 1 || f[0].Rule != c.rule {
			t.Errorf("%q: %+v, want %q", c.line, f, c.rule)
		}
	}
	for _, clean := range []string{"x := 1", "password = os.Getenv(\"P\")", `token = "short"`, "AK" + "IAshort", "mytodo := 1", "print(x)"} {
		if f := rule(t, clean); len(f) != 0 {
			t.Errorf("%q: %+v", clean, f)
		}
	}
}

func TestOnlyAddedLinesAreChecked(t *testing.T) {
	diff := "--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n-// TODO old\n // TODO context\n+ok\n"
	if f, added, _ := reviewer.Review([]byte(diff)); len(f) != 0 || added != 1 {
		t.Fatalf("%+v added=%d", f, added)
	}
}

func TestLineNumbersFollowHunksAndFiles(t *testing.T) {
	diff := "+++ b/a.go\n@@ -1 +10,2 @@\n+// TODO\n ctx\n@@ -9 +20 @@\n+// TODO\n+++ b/b.go\n@@ -1 +1 @@\n+// TODO\n"
	f, _, _ := reviewer.Review([]byte(diff))
	got := []string{}
	for _, x := range f {
		got = append(got, x.Path+":"+strconv.Itoa(x.Line))
	}
	if strings.Join(got, " ") != "a.go:10 a.go:20 b.go:1" {
		t.Fatalf("%v", got)
	}
}

func TestCRLFAndHostileHunkNumbers(t *testing.T) {
	f, _, _ := reviewer.Review([]byte("+++ b/x\r\n@@ -1 +1 @@\r\n+// TODO\r\n+y\r\n"))
	if len(f) != 1 || f[0].Line != 1 {
		t.Fatalf("%+v", f)
	}
	huge := "+++ b/x\n@@ -1 +" + strings.Repeat("9", 40) + " @@\n+// TODO\n"
	if f, _, _ := reviewer.Review([]byte(huge)); len(f) != 1 || f[0].Line <= 0 {
		t.Fatalf("%+v", f)
	}
}

func TestPathsAreReducedToASafeAlphabet(t *testing.T) {
	hostile := "+++ b/evil name$(rm -rf)\x1b[31m\t2024\n@@ -0,0 +1 @@\n+// TODO\n"
	f, _, _ := reviewer.Review([]byte(hostile))
	if len(f) != 1 || f[0].Path != "evil?name??rm?-rf???31m" {
		t.Fatalf("%+v", f)
	}
	if strings.ContainsAny(f[0].Path, " $()\x1b") {
		t.Fatalf("unsafe path %q", f[0].Path)
	}
	long := "+++ b/" + strings.Repeat("a", 500) + "\n@@ -0,0 +1 @@\n+// TODO\n"
	if f, _, _ := reviewer.Review([]byte(long)); len(f[0].Path) != reviewer.MaxPath {
		t.Fatalf("path length %d", len(f[0].Path))
	}
	// A name of exactly MaxPath characters is kept whole.
	exact := "+++ b/" + strings.Repeat("a", reviewer.MaxPath) + "\n@@ -0,0 +1 @@\n+// TODO\n"
	if f, _, _ := reviewer.Review([]byte(exact)); len(f[0].Path) != reviewer.MaxPath {
		t.Fatalf("path length %d", len(f[0].Path))
	}
}

func TestFindingsAreCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString("+++ b/x\n@@ -0,0 +1 @@\n")
	for i := 0; i < reviewer.MaxFindings+5; i++ {
		b.WriteString("+// TODO\n")
	}
	f, _, more := reviewer.Review([]byte(b.String()))
	if len(f) != reviewer.MaxFindings || !more {
		t.Fatalf("len=%d more=%v", len(f), more)
	}
	var exact strings.Builder
	exact.WriteString("+++ b/x\n@@ -0,0 +1 @@\n")
	for i := 0; i < reviewer.MaxFindings; i++ {
		exact.WriteString("+// TODO\n")
	}
	if f, _, more := reviewer.Review([]byte(exact.String())); len(f) != reviewer.MaxFindings || more {
		t.Fatalf("exactly the cap: len=%d more=%v", len(f), more)
	}
}

func TestRender(t *testing.T) {
	if got := reviewer.Render(nil, 0, false); got != "no added lines: nothing to review\n" {
		t.Errorf("%q", got)
	}
	if got := reviewer.Render(nil, 3, false); got != "no findings\n" {
		t.Errorf("%q", got)
	}
	got := reviewer.Render([]reviewer.Finding{{"a.go", 7, "leftover debug output"}}, reviewer.LargeDiff+1, true)
	want := "note: 501 added lines is too large to review well; split the change\n" +
		"a.go:7: leftover debug output\nmore findings than the 50 shown\n"
	if got != want {
		t.Errorf("%q", got)
	}
	if got := reviewer.Render(nil, reviewer.LargeDiff, false); got != "no findings\n" {
		t.Errorf("at the limit: %q", got)
	}
}

func task(content []byte, edit func(map[string]any)) string {
	m := map[string]any{"v": 1, "type": "task", "id": strings.Repeat("0", 32), "context": "c", "caller": "a@b", "owner": "a@b",
		"expires": "2030-01-01T00:00:00Z", "content": content}
	if edit != nil {
		edit(m)
	}
	b, _ := json.Marshal(m)
	return string(b) + "\n"
}

func run(t *testing.T, in string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := reviewer.Run(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("want exactly one line: %q", out.String())
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRunAnswersWithAResult(t *testing.T) {
	m := run(t, task([]byte(goodDiff), nil))
	if m["type"] != "result" {
		t.Fatalf("%v", m)
	}
	raw, _ := json.Marshal(m["content"])
	var text []byte
	_ = json.Unmarshal(raw, &text)
	if !strings.Contains(string(text), "main.go:5: possible secret: cloud access key id") {
		t.Fatalf("%q", text)
	}
	if strings.Contains(string(text), fakeKeyID) {
		t.Fatal("a matched secret was echoed")
	}
}

func TestRunRefusesWhatIsNotATask(t *testing.T) {
	for name, in := range map[string]string{
		"empty":         "",
		"not json":      "hello\n",
		"unknown field": task(nil, func(m map[string]any) { m["extra"] = 1 }),
		"wrong type":    task(nil, func(m map[string]any) { m["type"] = "answer" }),
		"wrong version": task(nil, func(m map[string]any) { m["v"] = 2 }),
		"trailing":      strings.TrimSuffix(task(nil, nil), "\n") + `{"a":1}` + "\n",
		"too long":      strings.Repeat("x", reviewer.MaxLine+1) + "\n",
	} {
		m := run(t, in)
		if m["type"] != "error" || m["message"] != reviewer.TextBadTask {
			t.Errorf("%s: %v", name, m)
		}
	}
}

func TestRunRefusesAnOversizedDiffButNotOneAtTheLimit(t *testing.T) {
	m := run(t, task(bytes.Repeat([]byte("a"), reviewer.MaxContent+1), nil))
	if m["type"] != "error" || m["message"] != reviewer.TextTooLarge {
		t.Fatalf("%.80v", m)
	}
	if m := run(t, task(bytes.Repeat([]byte("a"), reviewer.MaxContent), nil)); m["type"] != "result" {
		t.Fatalf("%.80v", m)
	}
}

func TestRunLongLineAcrossBufferBoundaries(t *testing.T) {
	// A task line larger than the read buffer is read whole.
	if m := run(t, task(bytes.Repeat([]byte("+x\n"), 100_000), nil)); m["type"] != "result" {
		t.Fatalf("%.80v", m)
	}
}

func TestRunReportsAWriteFailure(t *testing.T) {
	werr := errors.New("closed")
	if err := reviewer.Run(strings.NewReader(task(nil, nil)), failing{werr}); !errors.Is(err, werr) {
		t.Fatalf("%v", err)
	}
	if err := reviewer.Run(iotest.ErrReader(io.ErrUnexpectedEOF), failing{werr}); !errors.Is(err, werr) {
		t.Fatalf("%v", err)
	}
}

type failing struct{ err error }

func (f failing) Write([]byte) (int, error) { return 0, f.err }

func TestLimitsMatchTheDaemons(t *testing.T) {
	if reviewer.MaxContent != pipeline.MaxContent || reviewer.MaxLine != adapter.MaxLine {
		t.Fatal("the reviewer's limits drifted from the daemon's")
	}
}

// TestToolLess holds the package to its claim: it imports nothing that could run a program or reach the
// machine or network.
func TestToolLess(t *testing.T) {
	banned := map[string]bool{"os": true, "os/exec": true, "net": true, "net/http": true, "syscall": true, "unsafe": true,
		"plugin": true, "io/ioutil": true, "os/signal": true, "path/filepath": true, "fmt": true}
	files, _ := filepath.Glob("*.go")
	if len(files) < 2 {
		t.Fatal("no sources found")
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); banned[p] {
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
}
