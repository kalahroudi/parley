// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/bot"
)

// fakeGate is the owner: it records what it is asked and answers with allow (everything if nil).
type fakeGate struct {
	mu    sync.Mutex
	calls []gateCall
	ended int
	allow func(tool string, args []string) bool
	err   error
	wait  bool // call onWait
}

type gateCall struct {
	Tool string
	Args []string
}

func (g *fakeGate) Call(_ context.Context, _ bot.Task, tool string, args []string, onWait func()) (adapter.ToolReply, error) {
	g.mu.Lock()
	g.calls = append(g.calls, gateCall{tool, append([]string(nil), args...)})
	allow, err, wait := g.allow, g.err, g.wait
	g.mu.Unlock()
	if wait {
		onWait()
	}
	if err != nil {
		return adapter.ToolReply{}, err
	}
	if allow == nil || allow(tool, args) {
		return adapter.ToolReply{Outcome: adapter.OutcomeOK, Content: []byte("data")}, nil
	}
	return adapter.ToolReply{Outcome: "denied"}, nil
}

func (g *fakeGate) End([16]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ended++
}

func (g *fakeGate) got() []gateCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]gateCall(nil), g.calls...)
}

// gated is the ACP adapter running the script agent in dir, with the gate.
func gated(t testing.TB, dir string, g adapter.Tools, steps string) *adapter.ACP {
	t.Helper()
	a, err := adapter.NewACP(adapter.ACPConfig{Command: self(t), Dir: dir, Gate: g, Env: []string{helperEnv + "=acp-script", "PARLEY_SCRIPT=" + steps}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func send(v string) string { return "send " + v }

const sendChunk = `send {"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s1","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"%s"}}}}`

func chunkOf(text string) string { return strings.Replace(sendChunk, "%s", text, 1) }

func steps(s ...string) string { return strings.Join(s, "\x1e") }

func perm(id, title, kind, options string) string {
	return `send {"jsonrpc":"2.0","id":` + id + `,"method":"session/request_permission","params":{"sessionId":"s1","toolCall":{"toolCallId":"t","title":` + title + `,"kind":` + kind + `},"options":` + options + `}}`
}

const (
	allowReject = `[{"optionId":"always","name":"Always","kind":"allow_always"},{"optionId":"yes","name":"Allow","kind":"allow_once"},{"optionId":"no","name":"No","kind":"reject_once"}]`
	onlyAlways  = `[{"optionId":"always","name":"Always","kind":"allow_always"},{"optionId":"no","name":"No","kind":"reject_once"}]`
)

// run plays the script and returns the lines the client sent after the prompt, joined by newlines (echo n sends back line n).
func playOK(t *testing.T, a *adapter.ACP, tk bot.Task, s *stub) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := a.Handle(ctx, tk, s)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return string(res)
}

// A permission request is put to the owner with the kind and the title as plain text. Only the owner's yes, and only an
// allow_once option the agent offered, lets it through; every other answer is the reject option, and the owner is not
// asked when the agent offered nothing to allow. The task's waiting status is sent, and the gate is told the task is over.
func TestACPPermissionIsPutToTheOwner(t *testing.T) {
	for name, tc := range map[string]struct {
		options string
		allow   bool
		asked   bool
		want    string
	}{
		"allowed":            {allowReject, true, true, `{"outcome":{"optionId":"yes","outcome":"selected"}}`},
		"denied":             {allowReject, false, true, `{"outcome":{"optionId":"no","outcome":"selected"}}`},
		"only allow always":  {onlyAlways, true, false, `{"outcome":{"optionId":"no","outcome":"selected"}}`},
		"nothing to reject":  {`[{"optionId":"yes","name":"Allow","kind":"allow_once"}]`, false, true, `{"outcome":{"outcome":"cancelled"}}`},
		"no options at all":  {`[]`, true, false, `{"outcome":{"outcome":"cancelled"}}`},
		"allow once, no ids": {`[{"optionId":"","name":"Allow","kind":"allow_once"}]`, true, false, `{"outcome":{"outcome":"cancelled"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			g := &fakeGate{allow: func(string, []string) bool { return tc.allow }, wait: true}
			s := &stub{}
			title := `"Run \u0007rm -rf ‮/ ` + strings.Repeat("x", 300) + `"`
			out := playOK(t, gated(t, t.TempDir(), g, script(perm(`"p1"`, title, `"execute"`, tc.options), `read`, `echo 4`)), task, s)
			var reply struct {
				ID     string
				Result json.RawMessage
			}
			if err := json.Unmarshal([]byte(out), &reply); err != nil || reply.ID != "p1" || string(reply.Result) != tc.want {
				t.Fatalf("%s", out)
			}
			calls := g.got()
			if !tc.asked {
				if len(calls) != 0 {
					t.Fatalf("the owner was asked: %v", calls)
				}
				return
			}
			wantTitle := "Run ?rm -rf ?/ " + strings.Repeat("x", 256-len("Run ?rm -rf ?/ "))
			if len(calls) != 1 || calls[0].Tool != adapter.ToolACPPermission || !reflect.DeepEqual(calls[0].Args, []string{"execute", wantTitle}) {
				t.Fatalf("%+v", calls)
			}
			if len(s.statuses) != 1 || s.statuses[0] != adapter.TextToolWaiting {
				t.Fatalf("statuses %q", s.statuses)
			}
			if g.ended != 1 {
				t.Fatalf("the gate was told %d times that the task is over", g.ended)
			}
		})
	}
}

// With no gate nothing is put to anyone: a permission request is denied.
func TestACPWithoutAGateDeniesPermissions(t *testing.T) {
	a, err := adapter.NewACP(adapter.ACPConfig{Command: self(t), Dir: t.TempDir(),
		Env: []string{helperEnv + "=acp-script", "PARLEY_SCRIPT=" + script(perm(`1`, `"t"`, `"edit"`, allowReject), `read`, `echo 4`)}})
	if err != nil {
		t.Fatal(err)
	}
	if out := playOK(t, a, task, &stub{}); out != `{"jsonrpc":"2.0","id":1,"result":{"outcome":{"optionId":"no","outcome":"selected"}}}` {
		t.Fatalf("%s", out)
	}
}

func TestACPOffersTheFileSystemOnlyWithAGateAndNeverATerminal(t *testing.T) {
	for _, withGate := range []bool{false, true} {
		var gate adapter.Tools
		if withGate {
			gate = &fakeGate{}
		}
		a, err := adapter.NewACP(adapter.ACPConfig{Command: self(t), Dir: t.TempDir(), Gate: gate,
			Env: []string{helperEnv + "=acp-script", "PARLEY_SCRIPT=" + script(`echo 1`)}})
		if err != nil {
			t.Fatal(err)
		}
		out := playOK(t, a, task, &stub{})
		fs := strconv.FormatBool(withGate)
		for _, want := range []string{`"readTextFile":` + fs, `"writeTextFile":` + fs, `"terminal":false`, `"protocolVersion":1`} {
			if !strings.Contains(out, want) {
				t.Errorf("gate %v: %q not in %s", withGate, want, out)
			}
		}
	}
}

// A permission request the owner cannot be asked about ends the task when the task does; a failing gate is not a yes.
func TestACPGateErrorEndsTheTask(t *testing.T) {
	g := &fakeGate{err: errors.New("SECRET-CANARY gate")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := gated(t, t.TempDir(), g, script(perm(`1`, `"t"`, `"edit"`, allowReject), `read`)).Handle(ctx, task, &stub{})
	if !errors.Is(err, g.err) {
		t.Fatalf("%v", err)
	}
}

type fsCase struct {
	name   string
	method string
	params string // %D is the directory
	setup  func(t *testing.T, dir string)
	deny   bool
	want   string // the whole of the reply's result or error
	asked  []gateCall
	check  func(t *testing.T, dir string)
}

const (
	errDenied  = `"error":{"code":-32000,"message":"denied"}`
	errInvalid = `"error":{"code":-32602,"message":"invalid params"}`
	errFailed  = `"error":{"code":-32000,"message":"file operation failed"}`
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// File operations are put to the owner with the exact path, and done only on a yes, inside the directory.
func TestACPFileOperationsAreAskedAboutAndConfined(t *testing.T) {
	sum := sha256.Sum256([]byte("new"))
	sumHex := hex.EncodeToString(sum[:])
	read := func(dir, name string) gateCall {
		return gateCall{adapter.ToolACPRead, []string{filepath.Join(dir, name)}}
	}
	cases := []fsCase{
		{name: "read", method: "fs/read_text_file", params: `"path":"%D/a.txt"`, setup: func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "a.txt"), "one\ntwo\nthree\n") },
			want: `"result":{"content":"one\ntwo\nthree\n"}`},
		{name: "read some lines", method: "fs/read_text_file", params: `"path":"%D/a.txt","line":2,"limit":1`, setup: func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "a.txt"), "one\ntwo\nthree\n") },
			want: `"result":{"content":"two\n"}`},
		{name: "read from line 1", method: "fs/read_text_file", params: `"path":"%D/a.txt","line":1,"limit":1`, setup: func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "a.txt"), "one\ntwo\n") },
			want: `"result":{"content":"one\n"}`},
		{name: "read from a line", method: "fs/read_text_file", params: `"path":"%D/a.txt","line":3`, setup: func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "a.txt"), "one\ntwo\nthree\n") },
			want: `"result":{"content":"three\n"}`},
		{name: "read limit only", method: "fs/read_text_file", params: `"path":"%D/a.txt","limit":2`, setup: func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "a.txt"), "one\ntwo\nthree\n") },
			want: `"result":{"content":"one\ntwo\n"}`},
		{name: "read past the end", method: "fs/read_text_file", params: `"path":"%D/a.txt","line":99,"limit":5`, setup: func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "a.txt"), "one\n") },
			want: `"result":{"content":""}`},
		{name: "read limit past the end", method: "fs/read_text_file", params: `"path":"%D/a.txt","line":2,"limit":99`, setup: func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "a.txt"), "one\ntwo\n") },
			want: `"result":{"content":"two\n"}`},
		{name: "read nothing", method: "fs/read_text_file", params: `"path":"%D/a.txt","limit":0`, setup: func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "a.txt"), "one\n") },
			want: `"result":{"content":""}`},
		{name: "read denied", method: "fs/read_text_file", params: `"path":"%D/a.txt"`, deny: true, setup: func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "a.txt"), "SECRET-CANARY") },
			want: errDenied},
		{name: "read missing", method: "fs/read_text_file", params: `"path":"%D/none"`, want: errFailed},
		{name: "read a directory", method: "fs/read_text_file", params: `"path":"%D/sub"`, setup: func(t *testing.T, d string) { os.Mkdir(filepath.Join(d, "sub"), 0o700) }, want: errFailed},
		{name: "read binary", method: "fs/read_text_file", params: `"path":"%D/b"`, setup: func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "b"), "a\xffb") },
			want: `"error":{"code":-32000,"message":"not a text file"}`},
		{name: "read too large", method: "fs/read_text_file", params: `"path":"%D/big"`, setup: func(t *testing.T, d string) {
			writeFile(t, filepath.Join(d, "big"), strings.Repeat("a", adapter.MaxACPFile+1))
		},
			want: `"error":{"code":-32000,"message":"file too large"}`},
		{name: "read outside", method: "fs/read_text_file", params: `"path":"/etc/passwd"`, want: errInvalid, asked: []gateCall{}},
		{name: "read the directory itself", method: "fs/read_text_file", params: `"path":"%D"`, want: errInvalid, asked: []gateCall{}},
		{name: "read the parent", method: "fs/read_text_file", params: `"path":"%D/.."`, want: errInvalid, asked: []gateCall{}},
		{name: "read through dotdot", method: "fs/read_text_file", params: `"path":"%D/../x"`, want: errInvalid, asked: []gateCall{}},
		{name: "read a sibling with the same prefix", method: "fs/read_text_file", params: `"path":"%D-x/a"`, want: errInvalid, asked: []gateCall{}},
		{name: "read a relative path", method: "fs/read_text_file", params: `"path":"a.txt"`, want: errInvalid, asked: []gateCall{}},
		{name: "read a path with a control character", method: "fs/read_text_file", params: `"path":"%D/a\nb"`, want: errInvalid, asked: []gateCall{}},
		{name: "read a path with a bidi mark", method: "fs/read_text_file", params: `"path":"%D/a‮b"`, want: errInvalid, asked: []gateCall{}},
		{name: "read a path too long", method: "fs/read_text_file", params: `"path":"%D/` + strings.Repeat("a", 1100) + `"`, want: errInvalid, asked: []gateCall{}},
		{name: "read of another session", method: "fs/read_text_file", params: `"path":"%D/a.txt","sessionId":"other"`, want: errInvalid, asked: []gateCall{}},
		{name: "read with content", method: "fs/read_text_file", params: `"path":"%D/a.txt","content":"x"`, want: errInvalid, asked: []gateCall{}},
		{name: "read from line 0", method: "fs/read_text_file", params: `"path":"%D/a.txt","line":0`, want: errInvalid, asked: []gateCall{}},
		{name: "read a negative limit", method: "fs/read_text_file", params: `"path":"%D/a.txt","limit":-1`, want: errInvalid, asked: []gateCall{}},
		{name: "read without a path", method: "fs/read_text_file", params: `"x":1`, want: errInvalid, asked: []gateCall{}},
		{name: "write", method: "fs/write_text_file", params: `"path":"%D/w.txt","content":"new"`,
			setup: func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "w.txt"), "a much longer old content") },
			want:  `"result":null`, asked: []gateCall{{adapter.ToolACPWrite, []string{"%D/w.txt", "3", sumHex}}},
			check: func(t *testing.T, d string) {
				if b, err := os.ReadFile(filepath.Join(d, "w.txt")); err != nil || string(b) != "new" {
					t.Fatalf("%q %v", b, err)
				}
			}},
		{name: "write creates", method: "fs/write_text_file", params: `"path":"%D/n.txt","content":"new"`, want: `"result":null`,
			asked: []gateCall{{adapter.ToolACPWrite, []string{"%D/n.txt", "3", sumHex}}},
			check: func(t *testing.T, d string) {
				fi, err := os.Stat(filepath.Join(d, "n.txt"))
				if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
					t.Fatalf("%v %v", fi, err)
				}
			}},
		{name: "write denied", method: "fs/write_text_file", params: `"path":"%D/w.txt","content":"new"`, deny: true,
			setup: func(t *testing.T, d string) { writeFile(t, filepath.Join(d, "w.txt"), "old") }, want: errDenied,
			check: func(t *testing.T, d string) {
				if b, _ := os.ReadFile(filepath.Join(d, "w.txt")); string(b) != "old" {
					t.Fatalf("%q", b)
				}
			}},
		{name: "write outside", method: "fs/write_text_file", params: `"path":"/tmp/parley-acp-test-x","content":"new"`, want: errInvalid, asked: []gateCall{}},
		{name: "write without content", method: "fs/write_text_file", params: `"path":"%D/w.txt"`, want: errInvalid, asked: []gateCall{}},
		{name: "write into a missing directory", method: "fs/write_text_file", params: `"path":"%D/no/w.txt","content":"x"`, want: errFailed},
		{name: "write over a directory", method: "fs/write_text_file", params: `"path":"%D/sub","content":"x"`, setup: func(t *testing.T, d string) { os.Mkdir(filepath.Join(d, "sub"), 0o700) }, want: errFailed},
	}
	if runtime.GOOS != "windows" {
		cases = append(cases,
			fsCase{name: "read through a link that leaves the directory", method: "fs/read_text_file", params: `"path":"%D/link"`,
				setup: func(t *testing.T, d string) {
					out := t.TempDir()
					writeFile(t, filepath.Join(out, "secret"), "SECRET-CANARY")
					if err := os.Symlink(filepath.Join(out, "secret"), filepath.Join(d, "link")); err != nil {
						t.Fatal(err)
					}
				}, want: errFailed},
			fsCase{name: "write through a link that leaves the directory", method: "fs/write_text_file", params: `"path":"%D/link","content":"x"`,
				setup: func(t *testing.T, d string) {
					out := t.TempDir()
					writeFile(t, filepath.Join(out, "secret"), "old")
					if err := os.Symlink(filepath.Join(out, "secret"), filepath.Join(d, "link")); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if b, _ := os.ReadFile(filepath.Join(out, "secret")); string(b) != "old" {
							t.Errorf("the file outside was written: %q", b)
						}
					})
				}, want: errFailed},
		)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			params := strings.ReplaceAll(tc.params, "%D", filepath.ToSlash(dir))
			if runtime.GOOS == "windows" {
				params = strings.ReplaceAll(strings.ReplaceAll(tc.params, "%D", strings.ReplaceAll(dir, `\`, `\\`)), "/", `\\`)
			}
			if !strings.Contains(params, `"sessionId"`) {
				params += `,"sessionId":"s1"`
			}
			g := &fakeGate{allow: func(string, []string) bool { return !tc.deny }}
			line := `send {"jsonrpc":"2.0","id":7,"method":"` + tc.method + `","params":{` + params + `}}`
			out := playOK(t, gated(t, dir, g, script(line, `read`, `echo 4`)), task, &stub{})
			want := `{"jsonrpc":"2.0","id":7,` + tc.want + `}`
			if out != want {
				t.Fatalf("%.300s\nwant %.300s", out, want)
			}
			wantAsked := tc.asked
			if wantAsked == nil {
				if tc.method == "fs/read_text_file" {
					wantAsked = []gateCall{read(dir, strings.TrimPrefix(strings.Split(strings.Split(tc.params, `"path":"%D/`)[1], `"`)[0], ""))}
				} else {
					wantAsked = []gateCall{{adapter.ToolACPWrite, nil}}
				}
			}
			got := g.got()
			if len(got) != len(wantAsked) {
				t.Fatalf("asked %+v, want %+v", got, wantAsked)
			}
			for i := range got {
				for j := range wantAsked[i].Args {
					wantAsked[i].Args[j] = strings.ReplaceAll(wantAsked[i].Args[j], "%D/", dir+string(filepath.Separator))
				}
				if got[i].Tool != wantAsked[i].Tool || (wantAsked[i].Args != nil && !reflect.DeepEqual(got[i].Args, wantAsked[i].Args)) {
					t.Fatalf("asked %+v, want %+v", got, wantAsked)
				}
			}
			if tc.check != nil {
				tc.check(t, dir)
			}
		})
	}
}

// A file operation without a gate was not offered: it is "method not found", like a terminal request.
func TestACPFileAndTerminalRequestsWithoutAGateAreMethodNotFound(t *testing.T) {
	a, err := adapter.NewACP(adapter.ACPConfig{Command: self(t), Dir: t.TempDir(),
		Env: []string{helperEnv + "=acp-script", "PARLEY_SCRIPT=" + script(
			`send {"jsonrpc":"2.0","id":7,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/x"}}`, `read`, `echo 4`)}})
	if err != nil {
		t.Fatal(err)
	}
	if out := playOK(t, a, task, &stub{}); out != `{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"method not found"}}` {
		t.Fatalf("%s", out)
	}
	g := &fakeGate{}
	out := playOK(t, gated(t, t.TempDir(), g, script(`send {"jsonrpc":"2.0","id":8,"method":"terminal/create","params":{"sessionId":"s1","command":"ls"}}`, `read`, `echo 4`)), task, &stub{})
	if out != `{"jsonrpc":"2.0","id":8,"error":{"code":-32601,"message":"method not found"}}` || len(g.got()) != 0 {
		t.Fatalf("%s %v", out, g.got())
	}
}

// Requests put to the owner are bounded per task, refused ones included.
func TestACPRequestsToTheOwnerAreBounded(t *testing.T) {
	run := func(n int) error {
		var s []string
		for i := 0; i < n; i++ {
			s = append(s, perm(strconv.Itoa(i+1), `"t"`, `"edit"`, allowReject), `read`)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := gated(t, t.TempDir(), &fakeGate{}, script(s...)).Handle(ctx, task, &stub{})
		return err
	}
	if err := run(adapter.MaxACPPermissions); err != nil {
		t.Fatalf("%d requests: %v", adapter.MaxACPPermissions, err)
	}
	if err := run(adapter.MaxACPPermissions + 1); err == nil {
		t.Fatal("one request too many accepted")
	}
}

// A question is the end of a turn marked inputRequired: the caller is asked with the turn's text, and the answer is the next
// prompt of the same session, with the task id and the mark of an answer in _meta, and nothing of the task's other fields.
func TestACPQuestionIsAnswerByTheNextPrompt(t *testing.T) {
	question := steps(chunkOf("which?"), `send {"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn","_meta":{"parley":{"inputRequired":true}}}}`, `read`, `echo 4`,
		`send {"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}`)
	s := &stub{answer: "bl\"ue\n"}
	a, err := adapter.NewACP(adapter.ACPConfig{Command: self(t), Dir: t.TempDir(), Env: []string{helperEnv + "=acp-script", "PARLEY_SCRIPT=" + scriptStart + "\x1e" + question}})
	if err != nil {
		t.Fatal(err)
	}
	out := playOK(t, a, task, s)
	if !reflect.DeepEqual(s.asked, []string{"which?"}) {
		t.Fatalf("asked %q", s.asked)
	}
	want := `{"jsonrpc":"2.0","id":4,"method":"session/prompt","params":{"sessionId":"s1","prompt":[{"type":"text","text":"bl\"ue\u000a"}],"_meta":{"parley":{"task":"ab000000000000000000000000000000","answer":true}}}}`
	if out != want {
		t.Fatalf("%s", out)
	}
}

// The answer must be text; questions are bounded; an error of the caller's side ends the task.
func TestACPQuestionLimitsAndFailures(t *testing.T) {
	turn := func(id int) string {
		return steps(chunkOf("q"), `send {"jsonrpc":"2.0","id":`+strconv.Itoa(id)+`,"result":{"stopReason":"end_turn","_meta":{"parley":{"inputRequired":true}}}}`, `read`)
	}
	build := func(n int) string {
		s := scriptStart
		for i := 0; i < n; i++ {
			s += "\x1e" + turn(3+i)
		}
		return s + "\x1e" + `send {"jsonrpc":"2.0","id":` + strconv.Itoa(3+n) + `,"result":{"stopReason":"end_turn"}}`
	}
	run := func(script string, s *stub) error {
		a, err := adapter.NewACP(adapter.ACPConfig{Command: self(t), Dir: t.TempDir(), Env: []string{helperEnv + "=acp-script", "PARLEY_SCRIPT=" + script}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err = a.Handle(ctx, task, s)
		return err
	}
	if err := run(build(adapter.MaxQuestions), &stub{answer: "a"}); err != nil {
		t.Fatalf("%d questions: %v", adapter.MaxQuestions, err)
	}
	if err := run(build(adapter.MaxQuestions+1), &stub{answer: "a"}); err == nil {
		t.Fatal("one question too many accepted")
	}
	var f *bot.Failure
	if err := run(build(1), &stub{answer: "a\xff"}); !errors.As(err, &f) || f.Message != adapter.TextACPNotText {
		t.Fatalf("an answer that is not text: %v", err)
	}
	if err := run(build(1), &stub{askErr: context.Canceled}); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

// A plan's step in progress is the status; a repeat is not sent twice; a plan with no step in progress is dropped; the text
// is cut and made plain.
func TestACPPlanStepsAreStatuses(t *testing.T) {
	plan := func(entries string) string {
		return `send {"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s1","update":{"sessionUpdate":"plan","entries":` + entries + `}}}`
	}
	s := &stub{}
	long := strings.Repeat("é", adapter.MaxACPStatus)
	playOK(t, gated(t, t.TempDir(), nil, script(
		plan(`[{"content":"done","priority":"low","status":"completed"},{"content":"step one","priority":"low","status":"in_progress"},{"content":"later","priority":"low","status":"in_progress"}]`),
		plan(`[{"content":"step one","priority":"low","status":"in_progress"}]`),
		plan(`[{"content":"x","priority":"low","status":"pending"}]`),
		plan(`[{"content":"","priority":"low","status":"in_progress"}]`),
		plan(`[{"content":"a\u0007b‮c","priority":"low","status":"in_progress"}]`),
		plan(`[{"content":"`+long+`","priority":"low","status":"in_progress"}]`),
		plan(`[{"content":"step one","priority":"low","status":"in_progress"}]`),
	)), task, s)
	if len(s.statuses) != 4 || s.statuses[0] != "step one" || s.statuses[1] != "a?b?c" || s.statuses[2] != strings.Repeat("é", adapter.MaxACPStatus/2) || s.statuses[3] != "step one" {
		t.Fatalf("%q", s.statuses)
	}
}

// A declared failure is an error reply to the prompt with the marker; an error without it, or to any other request, says
// nothing to the caller; a refusal is a fixed failure; no other stop reason is success.
func TestACPFailuresAndStopReasons(t *testing.T) {
	prompt := func(reply string) string {
		a, err := adapter.NewACP(adapter.ACPConfig{Command: self(t), Dir: t.TempDir(), Env: []string{helperEnv + "=acp-script", "PARLEY_SCRIPT=" + scriptStart + "\x1e" + `send ` + reply}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err = a.Handle(ctx, task, &stub{})
		if err == nil {
			return ""
		}
		var f *bot.Failure
		if errors.As(err, &f) {
			return "failure: " + f.Message
		}
		if strings.Contains(err.Error(), "SECRET-CANARY") {
			t.Errorf("the error carries the agent's text: %v", err)
		}
		return "error"
	}
	for name, tc := range map[string]struct{ reply, want string }{
		"declared":           {`{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"no such file","data":{"parley":"failure"}}}`, "failure: no such file"},
		"other data":         {`{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"SECRET-CANARY","data":{"parley":"x"}}}`, "error"},
		"no data":            {`{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"SECRET-CANARY"}}`, "error"},
		"data not an object": {`{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"SECRET-CANARY","data":"failure"}}`, "error"},
		"refusal":            {`{"jsonrpc":"2.0","id":3,"result":{"stopReason":"refusal"}}`, "failure: " + adapter.TextACPRefused},
		"cancelled":          {`{"jsonrpc":"2.0","id":3,"result":{"stopReason":"cancelled"}}`, "error"},
		"max tokens":         {`{"jsonrpc":"2.0","id":3,"result":{"stopReason":"max_tokens"}}`, "error"},
		"no stop reason":     {`{"jsonrpc":"2.0","id":3,"result":{}}`, "error"},
		"result not object":  {`{"jsonrpc":"2.0","id":3,"result":5}`, "error"},
		"question and stop":  {`{"jsonrpc":"2.0","id":3,"result":{"stopReason":"cancelled","_meta":{"parley":{"inputRequired":true}}}}`, "error"},
		"plain end":          {`{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn","_meta":{"parley":{"inputRequired":false}}}}`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := prompt(tc.reply); got != tc.want {
				t.Fatalf("%q, want %q", got, tc.want)
			}
		})
	}
	// The marker means nothing on the replies to initialize and session/new.
	a, err := adapter.NewACP(adapter.ACPConfig{Command: self(t), Dir: t.TempDir(), Env: []string{helperEnv + "=acp-script", "PARLEY_SCRIPT=" + steps(`read`,
		`send {"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"SECRET-CANARY","data":{"parley":"failure"}}}`, `sleep`)}})
	if err != nil {
		t.Fatal(err)
	}
	var f *bot.Failure
	if _, err := a.Handle(context.Background(), task, &stub{}); err == nil || errors.As(err, &f) || strings.Contains(err.Error(), "SECRET-CANARY") {
		t.Fatalf("%v", err)
	}
}

// On cancel the agent is sent session/cancel, then has a moment to end itself, then is killed; Handle returns the
// context's error, and nothing is left running.
func TestACPCancelTellsTheAgentAndThenKillsIt(t *testing.T) {
	mark := filepath.Join(t.TempDir(), "mark")
	a := gated(t, t.TempDir(), nil, steps(scriptStart, `read`, `mark `+mark, `sleep`))
	base := runtime.NumGoroutine()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := a.Handle(ctx, task, &stub{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the agent that ignores session/cancel was waited for %v", d)
	}
	var b []byte
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if b, _ = os.ReadFile(mark); len(b) > 0 {
			break
		}
	}
	lines := strings.Split(string(b), "\n")
	if last := lines[len(lines)-1]; last != `{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s1"}}` {
		t.Fatalf("the agent was not told: %q", b)
	}
	for deadline := time.Now().Add(10 * time.Second); runtime.NumGoroutine() > base && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
	}
	if n := runtime.NumGoroutine(); n > base {
		t.Fatalf("%d goroutines before, %d after", base, n)
	}
}

// An agent that is waiting for the owner is ended by the task's end: the gate call is the one that returns.
func TestACPThroughTheHostWithAGate(t *testing.T) {
	g := &fakeGate{}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "hello")
	read := `send {"jsonrpc":"2.0","id":7,"method":"fs/read_text_file","params":{"sessionId":"s1","path":` + strconv.Quote(filepath.Join(dir, "a.txt")) + `}}`
	m := converseThroughHost(t, gated(t, dir, g, script(read, `read`, `echo 4`)), []byte("hi"))
	if last := m[len(m)-1]; last.Content != `{"jsonrpc":"2.0","id":7,"result":{"content":"hello"}}` {
		t.Fatalf("%+v", m)
	}
}

// Terminal access is deliberately not offered: initialize says so, and every terminal method is refused with the same
// error, with or without a gate, without asking the owner and without running anything, even for an agent that ignores the
// capability.
func TestACPTerminalIsNeverOfferedAndEveryTerminalMethodIsRefused(t *testing.T) {
	methods := []string{"terminal/create", "terminal/output", "terminal/wait_for_exit", "terminal/kill", "terminal/release"}
	for _, withGate := range []bool{false, true} {
		dir := t.TempDir()
		side := filepath.Join(dir, "side-effect")
		var s []string
		for i, m := range methods {
			s = append(s, `send {"jsonrpc":"2.0","id":`+strconv.Itoa(20+i)+`,"method":"`+m+`","params":{"sessionId":"s1","command":"touch","args":["`+filepath.ToSlash(side)+`"],"terminalId":"t1"}}`, `read`)
		}
		for i := range methods {
			s = append(s, `echo `+strconv.Itoa(4+i))
		}
		g := &fakeGate{}
		var gate adapter.Tools
		if withGate {
			gate = g
		}
		a, err := adapter.NewACP(adapter.ACPConfig{Command: self(t), Dir: dir, Gate: gate,
			Env: []string{helperEnv + "=acp-script", "PARLEY_SCRIPT=" + script(append([]string{`echo 1`}, s...)...)}})
		if err != nil {
			t.Fatal(err)
		}
		out := playOK(t, a, task, &stub{})
		if !strings.Contains(out, `"terminal":false`) {
			t.Errorf("gate %v: the terminal capability is advertised: %s", withGate, out)
		}
		for i := range methods {
			want := `{"jsonrpc":"2.0","id":` + strconv.Itoa(20+i) + `,"error":{"code":-32601,"message":"method not found"}}`
			if !strings.Contains(out, want) {
				t.Errorf("gate %v, %s: %s not in %s", withGate, methods[i], want, out)
			}
		}
		if _, err := os.Stat(side); err == nil {
			t.Errorf("gate %v: a terminal request had a side effect", withGate)
		}
		if n := len(g.got()); n != 0 {
			t.Errorf("the owner was asked %d times about a terminal", n)
		}
	}
}
