// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package reviewer is the reference tool-less bot: it reads a unified diff and
// answers with findings. It is the template for a bot run by the CLI adapter
// ("parley-bot/1", see internal/adapter): one task line on standard input, one
// result or error line on standard output.
//
// Tool-less means exactly this, and tests hold it to it:
//
//   - the review is a pure function of the task content: no program is run, no
//     file or network is touched, no environment is read. The package itself imports
//     none of os, os/exec, net, syscall, unsafe or plugin (TestToolLess checks its
//     imports; the standard library it builds on links some of them, but nothing
//     here calls them);
//   - the task is data. The diff is scanned, never obeyed: nothing in it can
//     change what the bot does, and no text of it reaches the answer except a
//     file name reduced to a safe alphabet and cut short. In particular a
//     matched secret is reported by file and line only, never echoed;
//   - output is bounded (MaxFindings lines of at most MaxLineText bytes).
//
// Because it is tool-less, its approval mode is "none" (see internal/skill).
// What it is not: a model. The rules are a few deterministic checks that
// make a sound template and a useful smoke test; a customer's reviewer would
// put a model behind the same line protocol and must treat the diff as untrusted
// input too.
package reviewer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Limits. MaxContent and MaxLine mirror the daemon's (pipeline.MaxContent and
// adapter.MaxLine); a test pins them to those values.
const (
	MaxContent  = 1<<19 - 2<<10
	MaxLine     = (MaxContent+1+2)/3*4 + 4096
	MaxFindings = 50
	MaxPath     = 80
	// LargeDiff is the number of added lines above which the review says the change is too big to review well.
	LargeDiff = 500
)

// Fixed error texts for the caller. None holds task content.
const (
	TextBadTask  = "the task is not a review request"
	TextTooLarge = "the diff is too large to review"
)

// Finding is one remark: a file and an added line (the line number in the new file) and a fixed message.
type Finding struct {
	Path string
	Line int
	Rule string
}

type rule struct {
	id string
	re *regexp.Regexp
}

// Rules run on added lines. Their messages are literals, so the answer never carries diff text.
var rules = []rule{
	{"possible secret: private key", regexp.MustCompile(`-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}`)},
	{"possible secret: cloud access key id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"possible secret: credential assigned a literal", regexp.MustCompile(`(?i)(api[_-]?key|secret|token|passw(or)?d)["']?\s*(?::=|[:=])\s*["'][^"'\s]{8,}["']`)},
	{"leftover debug output", regexp.MustCompile(`\bconsole\.log\(|\bdebugger\b|\bfmt\.Print(ln|f)?\(`)},
	{"unfinished work marker", regexp.MustCompile(`\b(TODO|FIXME|XXX)\b`)},
	{"trailing whitespace", regexp.MustCompile(`[ \t]+$`)},
}

var hunk = regexp.MustCompile(`^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// count reads a hunk length: absent means 1; a number too large to matter is capped.
func count(s string) int {
	if s == "" {
		return 1
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > 1<<30 {
		return 1 << 30
	}
	return n
}

// Review scans a unified diff. Anything that is not a diff yields no findings
// (and the caller is told). Findings come in diff order, at most MaxFindings; the
// second result is true when there were more.
func Review(diff []byte) (findings []Finding, added int, more bool) {
	path, line := "", 0
	oldLeft, newLeft := 0, 0 // lines the current hunk still owes: inside it, "+++ x" is an added line "++ x", not a header
	for _, l := range strings.Split(string(diff), "\n") {
		l = strings.TrimSuffix(l, "\r")
		inHunk := oldLeft > 0 || newLeft > 0
		switch {
		case inHunk && strings.HasPrefix(l, "-"):
			oldLeft--
		case inHunk && strings.HasPrefix(l, "\\"): // "\ No newline at end of file"
		case !inHunk && strings.HasPrefix(l, "+++ "):
			path = safePath(strings.TrimPrefix(strings.TrimPrefix(l[4:], "b/"), "a/"))
			line = 0
		case !inHunk && strings.HasPrefix(l, "--- "):
		case !inHunk && hunk.MatchString(l):
			m := hunk.FindStringSubmatch(l)
			line, _ = strconv.Atoi(m[2]) // out of range gives the largest int: the number is only a label
			oldLeft, newLeft = count(m[1]), count(m[3])
		case strings.HasPrefix(l, "+"):
			newLeft--
			added++
			for _, r := range rules {
				if r.re.MatchString(l[1:]) {
					if len(findings) == MaxFindings {
						more = true
					} else {
						findings = append(findings, Finding{path, line, r.id})
					}
				}
			}
			line++
		case strings.HasPrefix(l, " "), inHunk && l == "": // a context line whose lone space was stripped
			oldLeft--
			newLeft--
			line++
		}
	}
	return findings, added, more
}

// safePath keeps file names to a harmless alphabet and length: a name comes from the
// task, which is data from a stranger.
func safePath(p string) string {
	if i := strings.IndexByte(p, '\t'); i >= 0 {
		p = p[:i]
	}
	out := make([]byte, 0, MaxPath)
	for i := 0; i < len(p) && len(out) < MaxPath; i++ {
		c := p[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '/' {
			out = append(out, c)
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
}

// Render is the text answer.
func Render(findings []Finding, added int, more bool) string {
	var b strings.Builder
	if added == 0 {
		return "no added lines: nothing to review\n"
	}
	if added > LargeDiff {
		b.WriteString("note: " + strconv.Itoa(added) + " added lines is too large to review well; split the change\n")
	}
	if len(findings) == 0 {
		b.WriteString("no findings\n")
		return b.String()
	}
	for _, f := range findings {
		b.WriteString(f.Path + ":" + strconv.Itoa(f.Line) + ": " + f.Rule + "\n")
	}
	if more {
		b.WriteString("more findings than the " + strconv.Itoa(MaxFindings) + " shown\n")
	}
	return b.String()
}

type taskLine struct {
	V       int    `json:"v"`
	Type    string `json:"type"`
	ID      string `json:"id"`
	Context string `json:"context"`
	Caller  string `json:"caller"`
	Owner   string `json:"owner"`
	Expires string `json:"expires"`
	Content []byte `json:"content"`
}

type outLine struct {
	Type    string `json:"type"`
	Content []byte `json:"content,omitempty"`
	Message string `json:"message,omitempty"`
}

var errLong = errors.New("reviewer: line too long")

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		part, more, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		if len(line)+len(part) > MaxLine {
			return nil, errLong
		}
		line = append(line, part...)
		if !more {
			return line, nil
		}
	}
}

// Run serves one task: it reads the task line from in and writes one result or
// error line to out. It returns an error only when out cannot be written.
func Run(in io.Reader, out io.Writer) error {
	reply := func(o outLine) error {
		b, _ := json.Marshal(o) // strings and bytes: cannot fail
		_, err := out.Write(append(b, '\n'))
		return err
	}
	fail := func(msg string) error { return reply(outLine{Type: "error", Message: msg}) }
	line, err := readLine(bufio.NewReaderSize(in, 64<<10))
	if err != nil {
		return fail(TextBadTask)
	}
	var t taskLine
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if dec.Decode(&t) != nil || dec.More() || t.V != 1 || t.Type != "task" {
		return fail(TextBadTask)
	}
	if len(t.Content) > MaxContent {
		return fail(TextTooLarge)
	}
	findings, added, more := Review(t.Content)
	return reply(outLine{Type: "result", Content: []byte(Render(findings, added, more))})
}
