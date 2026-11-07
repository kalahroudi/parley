// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// acpAgent is the agent the ACP adapter runs in these tests (this test binary, see TestMain). The mode says how it
// behaves; the ones that need more read PARLEY_RAW (a line sent instead of the reply to initialize), PARLEY_N, PARLEY_METHOD
// and PARLEY_REQ (a flood of N messages, requests with an id if PARLEY_REQ is set, before the conversation starts).
func acpAgent(mode string) {
	in := bufio.NewReaderSize(os.Stdin, 1<<22)
	var mu sync.Mutex
	out := func(format string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(os.Stdout, format+"\n", a...)
	}
	read := func() (map[string]json.RawMessage, string) {
		line, _ := in.ReadString('\n')
		var m map[string]json.RawMessage
		json.Unmarshal([]byte(line), &m)
		return m, line
	}
	chunk := func(kind, typ, text string) {
		q, _ := json.Marshal(text)
		out(`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s1","update":{"sessionUpdate":%q,"content":{"type":%q,"text":%s}}}}`, kind, typ, q)
	}
	_, init := read()
	switch mode {
	case "acp-raw":
		out("%s", strings.ReplaceAll(os.Getenv("PARLEY_RAW"), `\n`, "\n"))
		time.Sleep(time.Minute)
	case "acp-hang":
		time.Sleep(time.Minute)
	case "acp-version":
		out(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":2}}`)
		time.Sleep(time.Minute)
	}
	if n, _ := strconv.Atoi(os.Getenv("PARLEY_N")); n > 0 {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 1; i <= n; i++ {
				if os.Getenv("PARLEY_REQ") != "" {
					out(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":{}}`, i, os.Getenv("PARLEY_METHOD"))
				} else {
					out(`{"jsonrpc":"2.0","method":%q,"params":{}}`, os.Getenv("PARLEY_METHOD"))
				}
			}
		}()
		for i := 0; os.Getenv("PARLEY_REQ") != "" && i < n; i++ {
			read() // the replies
		}
		wg.Wait()
	}
	out(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentCapabilities":{"loadSession":false,"future":true}}}`)
	_, newSession := read()
	if mode == "acp-closein" { // stops reading before the prompt is sent
		os.Stdin.Close()
	}
	if mode == "acp-error" {
		out(`{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"SECRET-CANARY"}}`)
		time.Sleep(time.Minute)
	}
	out(`{"jsonrpc":"2.0","id":2,"result":{"sessionId":"s1"}}`)
	_, prompt := read()
	switch mode {
	case "acp-echo": // the three requests it was sent, as the result
		chunk("agent_message_chunk", "text", init+newSession+prompt)
	case "acp-big":
		for i := 0; i < 8; i++ {
			chunk("agent_message_chunk", "text", strings.Repeat("a", 100000))
		}
		time.Sleep(time.Minute)
		return
	case "acp-wrongsession":
		out(`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"zzz","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"x"}}}}`)
		time.Sleep(time.Minute)
	case "acp-refuse":
		out(`{"jsonrpc":"2.0","id":3,"result":{"stopReason":"refusal"}}`)
		return
	case "acp-flood": // the flood above is all it sends that the adapter does not use
		chunk("agent_message_chunk", "text", "done")
	default: // "acp" and "acp-noreject"
		chunk("agent_thought_chunk", "text", "SECRET-CANARY thinking")
		out(`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s1","update":{"sessionUpdate":"tool_call_update","toolCallId":"t","content":[{"type":"content","content":{"type":"text","text":"SECRET-CANARY"}}]}}}`)
		chunk("agent_message_chunk", "image", "SECRET-CANARY")
		opts := `[{"optionId":"yes","name":"Allow","kind":"allow_once"},{"optionId":"no","name":"Reject","kind":"reject_once"}]`
		if mode == "acp-noreject" {
			opts = `[{"optionId":"yes","name":"Allow","kind":"allow_once"}]`
		}
		out(`{"jsonrpc":"2.0","id":"perm-1","method":"session/request_permission","params":{"sessionId":"s1","toolCall":{"toolCallId":"t"},"options":%s}}`, opts)
		perm, _ := read()
		out(`{"jsonrpc":"2.0","id":9,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/etc/passwd"}}`)
		fs, _ := read()
		chunk("agent_message_chunk", "text", "hello ")
		chunk("agent_message_chunk", "text", "wörld")
		chunk("agent_message_chunk", "text", fmt.Sprintf("|%s|%s|%s|%s", perm["id"], perm["result"], fs["id"], fs["error"]))
	}
	out(`{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}`)
}

func acp(t testing.TB, mode string, extra ...string) *adapter.ACP {
	t.Helper()
	a, err := adapter.NewACP(adapter.ACPConfig{Command: self(t), Dir: t.TempDir(), Env: append([]string{helperEnv + "=" + mode}, extra...)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func handle(t *testing.T, a *adapter.ACP, tk bot.Task) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := a.Handle(ctx, tk, &stub{})
	if ctx.Err() != nil {
		t.Fatalf("the agent was waited for until the deadline: %v", err)
	}
	return res, err
}

const permOK = `{"outcome":{"optionId":"no","outcome":"selected"}}`

// An agent that asks, reads, thinks and reports progress: only its message text is the result, a permission request is
// denied with the reject option it offered, a file request is "method not found", and its thoughts and non-text blocks go nowhere.
func TestACPResultIsTheMessageTextAndEverythingElseIsRefused(t *testing.T) {
	res, err := handle(t, acp(t, "acp"), task)
	want := `hello wörld|"perm-1"|` + permOK + `|9|{"code":-32601,"message":"method not found"}`
	if err != nil || string(res) != want {
		t.Fatalf("%q %v", res, err)
	}
	res, err = handle(t, acp(t, "acp-noreject"), task)
	if err != nil || !strings.Contains(string(res), `|{"outcome":{"outcome":"cancelled"}}|`) {
		t.Fatalf("%q %v", res, err)
	}
}

// The agent is offered nothing, gets the session's directory, and the task reaches it as one text block with its names as
// data fields: nothing of the task is mixed into text.
func TestACPSendsTheTaskAsOnePromptAndOffersNothing(t *testing.T) {
	dir := t.TempDir()
	a, err := adapter.NewACP(adapter.ACPConfig{Command: self(t), Dir: dir, Env: []string{helperEnv + "=acp-echo"}})
	if err != nil {
		t.Fatal(err)
	}
	tk := task
	tk.Content = []byte("line1\nline2 \"q\" \\ \x01 é €")
	tk.Caller = "dev\"}, \"x\": {"
	res, err := handle(t, a, tk)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(res), "\n")
	if len(lines) != 4 || lines[3] != "" {
		t.Fatalf("%q", res)
	}
	var init, ns, pr map[string]any
	for i, p := range []*map[string]any{&init, &ns, &pr} {
		if err := json.Unmarshal([]byte(lines[i]), p); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
	}
	caps, _ := json.Marshal(init["params"])
	if string(caps) != `{"clientCapabilities":{"fs":{"readTextFile":false,"writeTextFile":false},"terminal":false},"clientInfo":{"name":"parley","title":"Parley","version":"1"},"protocolVersion":1}` {
		t.Errorf("%s", caps)
	}
	nsp := ns["params"].(map[string]any)
	if servers, ok := nsp["mcpServers"].([]any); nsp["cwd"] != dir || !ok || len(servers) != 0 || len(nsp) != 2 {
		t.Errorf("%v", nsp)
	}
	p := pr["params"].(map[string]any)
	block := p["prompt"].([]any)
	if p["sessionId"] != "s1" || len(block) != 1 || block[0].(map[string]any)["text"] != string(tk.Content) {
		t.Errorf("%v", p)
	}
	meta := p["_meta"].(map[string]any)["parley"].(map[string]any)
	if meta["caller"] != tk.Caller || meta["owner"] != tk.Owner || meta["context"] != tk.Context || len(meta) != 5 {
		t.Errorf("%v", meta)
	}
}

func TestACPRefusesATaskThatIsNotTextBeforeStartingAnything(t *testing.T) {
	a, err := adapter.NewACP(adapter.ACPConfig{Command: filepath.Join(t.TempDir(), "not-there"), Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	tk := task
	tk.Content = []byte("ok \xff\xfe")
	var f *bot.Failure
	if _, err := a.Handle(context.Background(), tk, &stub{}); !errors.As(err, &f) || f.Message != adapter.TextACPNotText {
		t.Fatalf("%v", err)
	}
}

func TestACPConfigRejectsWhatCLIRejectsAndAMissingDirectory(t *testing.T) {
	abs, dir := self(t), t.TempDir()
	for name, cfg := range map[string]adapter.ACPConfig{
		"no directory":       {Command: abs},
		"relative directory": {Command: abs, Dir: "x"},
		"relative command":   {Command: "bot", Dir: dir},
		"env without =":      {Command: abs, Dir: dir, Env: []string{"A"}},
		"NUL in arg":         {Command: abs, Dir: dir, Args: []string{"a\x00"}},
	} {
		if _, err := adapter.NewACP(cfg); !errors.Is(err, adapter.ErrACPConfig) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if _, err := adapter.NewACP(adapter.ACPConfig{Command: abs, Dir: dir, Args: []string{"--acp"}, Env: []string{"A=b"}}); err != nil {
		t.Fatal(err)
	}
}

// Whatever the agent sends instead of the conversation ends the task with an error that is not the agent's text.
func TestACPHostileAgentsEndTheTaskWithoutTheirWords(t *testing.T) {
	long := strings.Repeat("a", 100)
	for name, tc := range map[string]struct {
		mode string
		raw  string
	}{
		"exits at once":                        {mode: "exit"},
		"not the protocol":                     {mode: "garbage"},
		"a line that never ends":               {mode: "noline"},
		"an error reply":                       {mode: "acp-error"},
		"another protocol version":             {mode: "acp-version"},
		"a refusal":                            {mode: "acp-refuse"},
		"updates for another session":          {mode: "acp-wrongsession"},
		"a reply with the wrong id":            {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":7,"result":{"protocolVersion":1}}`},
		"a duplicate key":                      {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1},"id":7}`},
		"an unknown field":                     {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1},"x":"SECRET-CANARY"}`},
		"two messages in a line":               {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":1,"result":{}} {"jsonrpc":"2.0","id":1,"result":{}}`},
		"trailing text":                        {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":1,"result":{}} SECRET-CANARY`},
		"the old protocol":                     {mode: "acp-raw", raw: `{"jsonrpc":"1.0","id":1,"result":{"protocolVersion":1}}`},
		"a reply that is both":                 {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":1,"result":{},"error":{}}`},
		"a null request id":                    {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":null,"method":"fs/read_text_file"}`},
		"a request id too long":                {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":"` + long + `","method":"x"}`},
		"a reply without a version":            {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"1"}}`},
		"a session id past the limit":          {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}` + "\n" + `{"jsonrpc":"2.0","id":2,"result":{"sessionId":"` + strings.Repeat("s", 257) + `"}}`},
		"no session id":                        {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}` + "\n" + `{"jsonrpc":"2.0","id":2,"result":{}}`},
		"a prompt reply without a stop reason": {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}` + "\n" + `{"jsonrpc":"2.0","id":2,"result":{"sessionId":"s"}}` + "\n" + `{"jsonrpc":"2.0","id":3,"result":{}}`},
		"a message chunk that is not one":      {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}` + "\n" + `{"jsonrpc":"2.0","id":2,"result":{"sessionId":"s"}}` + "\n" + `{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":[1]}}}`},
		"an update that is not an object":      {mode: "acp-raw", raw: `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}` + "\n" + `{"jsonrpc":"2.0","id":2,"result":{"sessionId":"s"}}` + "\n" + `{"jsonrpc":"2.0","method":"session/update","params":7}`},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			start := time.Now()
			raw := strings.ReplaceAll(tc.raw, "\n", "\\n") // one environment value; the helper turns it back
			_, err := acp(t, tc.mode, "PARLEY_RAW="+raw).Handle(ctx, task, &stub{})
			var f *bot.Failure
			if err == nil || errors.As(err, &f) || ctx.Err() != nil || strings.Contains(err.Error(), "SECRET-CANARY") {
				t.Fatalf("%v (ctx %v)", err, ctx.Err())
			}
			if time.Since(start) > 10*time.Second {
				t.Fatal("the hostile agent was waited for")
			}
		})
	}
}

// Floods of messages the adapter does not use are cut at a fixed number; one fewer is fine.
func TestACPFloodsAreBounded(t *testing.T) {
	for name, tc := range map[string]struct {
		method string
		req    string
		limit  int
	}{
		"notifications":         {"x/y", "", adapter.MaxACPIgnored},
		"requests for a method": {"fs/write_text_file", "1", adapter.MaxACPIgnored},
		"permission requests":   {"session/request_permission", "1", adapter.MaxACPPermissions},
	} {
		t.Run(name, func(t *testing.T) {
			run := func(n int) error {
				_, err := handle(t, acp(t, "acp-flood", "PARLEY_METHOD="+tc.method, "PARLEY_REQ="+tc.req, "PARLEY_N="+strconv.Itoa(n)), task)
				return err
			}
			if err := run(tc.limit); err != nil {
				t.Fatalf("%d messages: %v", tc.limit, err)
			}
			if err := run(tc.limit + 1); err == nil {
				t.Fatalf("%d messages accepted", tc.limit+1)
			}
		})
	}
}

func TestACPAgentThatStoppedReadingFailsTheTask(t *testing.T) {
	tk := task
	tk.Content = []byte(strings.Repeat("a", 1<<20)) // more than a pipe holds
	if _, err := handle(t, acp(t, "acp-closein"), tk); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

func TestACPCommandThatCannotStartOrBeContainedFailsWithoutNamingIt(t *testing.T) {
	a, err := adapter.NewACP(adapter.ACPConfig{Command: filepath.Join(t.TempDir(), "SECRET-CANARY-missing"), Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Handle(context.Background(), task, &stub{}); err == nil || strings.Contains(err.Error(), "SECRET-CANARY") {
		t.Fatalf("%v", err)
	}
	restore := adapter.SetContain(func(*exec.Cmd) (func(), error) { return nil, errors.New("no job") })
	defer restore()
	if _, err = acp(t, "acp").Handle(context.Background(), task, &stub{}); err == nil || strings.Contains(err.Error(), "no job") {
		t.Fatalf("%v", err)
	}
}

func TestACPDeadlineKillsAnAgentThatNeverAnswers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := acp(t, "acp-hang").Handle(ctx, task, &stub{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err := acp(t, "acp-hang").Handle(ctx2, task, &stub{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

// Through the real Host: a result, a reply past the limit (cut as soon as it is too large, the agent killed with the
// task) and an agent's error text, which never reaches the caller. No goroutine or child outlives the Host.
func TestACPThroughTheHost(t *testing.T) {
	m := converseThroughHost(t, acp(t, "acp"), []byte("hi"))
	if last := m[len(m)-1]; last.Type != envelope.TypeResult || !strings.HasPrefix(last.Content, "hello wörld|") {
		t.Fatalf("%+v", m)
	}
	start := time.Now()
	m = converseThroughHost(t, acp(t, "acp-big"), []byte("hi"))
	if last := m[len(m)-1]; last.Type != envelope.TypeError || last.Content != bot.TextTooLarge || len(m) != 1 {
		t.Fatalf("%+v", m)
	}
	if time.Since(start) > 20*time.Second {
		t.Fatal("the oversized reply was read to the end")
	}
	m = converseThroughHost(t, acp(t, "acp-error"), []byte("hi"))
	if last := m[len(m)-1]; last.Type != envelope.TypeError || last.Content != bot.TextFailed {
		t.Fatalf("%+v", m)
	}
}

// The result may be exactly as large as a result can be; one byte more is cut to one byte more than that.
func TestACPCutsTheReplyJustPastTheLimit(t *testing.T) {
	res, err := handle(t, acp(t, "acp-big"), task)
	if err != nil || len(res) != pipeline.MaxContent+1 {
		t.Fatalf("%d %v", len(res), err)
	}
}
