// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/adapter/adaptertest"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/bot/bottest"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/pipeline"
)

// Hostile input, both ways, through the real Host and the real adapters. What a bot says and what a task carries are
// both data from someone who does not have to be honest. The unit tests of each piece pin their own rules; these
// check the promise the caller sees: one bounded final message, no text of the bot's own or its transport's unless the
// bot declared it as an error, and a task that reaches the bot as one well-formed line however its fields are made.

const canary = "SECRET-CANARY"

func isFinal(t envelope.Type) bool {
	return t != envelope.TypeStatus && t != envelope.TypeInputRequired
}

// converseThroughHost runs one task on b behind a Host, answers every question with "a", and returns what the caller
// was sent up to and including the final message. It fails if no final message comes.
func converseThroughHost(t *testing.T, b bot.Bot, content []byte) []bottest.Message {
	t.Helper()
	return converseWithin(t, b, content, 30*time.Second)
}

// converseWithin is converseThroughHost with the longest a task may run.
func converseWithin(t *testing.T, b bot.Bot, content []byte, limit time.Duration) []bottest.Message {
	t.Helper()
	rec := bottest.NewRecorder()
	base := runtime.NumGoroutine()
	h, err := bot.NewHost(bot.Config{Bot: b, Responder: rec, Timeout: limit})
	if err != nil {
		t.Fatal(err)
	}
	// Whatever the bot did, nothing of the task may outlive the Host: no reader, no child, no request.
	defer func() {
		h.Close()
		deadline := time.Now().Add(10 * time.Second)
		for runtime.NumGoroutine() > base && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if n := runtime.NumGoroutine(); n > base {
			t.Errorf("%d goroutines before the task, %d after the host was closed", base, n)
		}
	}()
	id := [16]byte{9}
	h.Inbound(pipeline.Inbound{Type: envelope.TypeTask, TaskID: id, Caller: "d", Owner: "o", Context: "c", Content: content})
	answered := 0
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		msgs := rec.Messages(id)
		asked := 0
		for _, m := range msgs {
			if m.Type == envelope.TypeInputRequired {
				asked++
			}
		}
		for ; answered < asked; answered++ {
			h.Inbound(pipeline.Inbound{Type: envelope.TypeReply, TaskID: id, Content: []byte("a")})
		}
		if n := len(msgs); n > 0 && isFinal(msgs[n-1].Type) {
			time.Sleep(50 * time.Millisecond) // anything the bot manages to add after its final message
			return rec.Messages(id)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no final message")
	return nil
}

// A bot service that speaks first, and then only answers a cancel notice or an answer with the next lines.
func hostileAPI(t *testing.T, body func(n int) string) *adapter.API {
	var n int
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		line, _ := bufio.NewReaderSize(r.Body, 1<<22).ReadBytes('\n')
		if bytes.Contains(line, []byte(`"type":"cancel"`)) {
			return
		}
		n++
		fmt.Fprint(w, body(n))
	})
	return api(t, srv.URL, "")
}

type stream struct {
	out   string
	times int
}

func (s stream) body(int) string { return strings.Repeat(s.out, s.times) }

// Whatever the bot streams, the caller sees only fixed text for a broken bot, at most the bounded number of messages,
// and exactly one final message.
func TestHostileBotStreamsReachTheCallerAsFixedErrors(t *testing.T) {
	good := `{"type":"result","content":"aGk="}` + "\n"
	status := `{"type":"status","content":"aGk="}` + "\n"
	for name, s := range map[string]stream{
		"not json":             {canary + "\n", 1},
		"unknown field":        {`{"type":"result","content":"aGk=","extra":"` + canary + `"}` + "\n", 1},
		"trailing text":        {`{"type":"result","content":"aGk="} ` + canary + "\n", 1},
		"two values":           {strings.TrimSuffix(good, "\n") + good, 1},
		"unknown type":         {`{"type":"` + canary + `"}` + "\n", 1},
		"content not a string": {`{"type":"result","content":123}` + "\n", 1},
		"not base64":           {`{"type":"result","content":"` + canary + `"}` + "\n", 1},
		"error as the content": {`{"type":"error","message":1,"content":"` + canary + `"}` + "\n", 1},
		"status flood":         {status, adapter.MaxStatuses + 1},
		"question flood":       {`{"type":"question","content":"cQ=="}` + "\n", adapter.MaxQuestions + 1},
		"ends without final":   {status, 1},
		"line past the limit":  {strings.Repeat("a", 4096), 2*adapter.MaxLine/4096 + 8},
	} {
		check := func(t *testing.T, msgs []bottest.Message) {
			t.Helper()
			var statuses, questions int
			for i, m := range msgs {
				switch {
				case m.Type == envelope.TypeStatus:
					statuses++
				case m.Type == envelope.TypeInputRequired:
					questions++
				case i != len(msgs)-1:
					t.Fatalf("a final message that is not last: %+v", msgs)
				case m.Type != envelope.TypeError || m.Content != bot.TextFailed:
					t.Fatalf("the caller was shown %v %q", m.Type, m.Content)
				}
			}
			if statuses > adapter.MaxStatuses || questions > adapter.MaxQuestions {
				t.Fatalf("%d statuses and %d questions got through", statuses, questions)
			}
			if !isFinal(msgs[len(msgs)-1].Type) {
				t.Fatal("no final message")
			}
		}
		t.Run("API/"+name, func(t *testing.T) {
			a := hostileAPI(t, func(int) string { return s.body(0) })
			check(t, converseThroughHost(t, a, []byte("x")))
		})
		t.Run("CLI/"+name, func(t *testing.T) {
			c := cli(t, "emit", "PARLEY_OUT="+s.out, "PARLEY_N="+strconv.Itoa(s.times))
			check(t, converseThroughHost(t, c, []byte("x")))
		})
	}
}

// A bot that ends in a question every time it is answered is stopped at the question limit, over HTTP where every
// answer is a new request.
func TestHostileBotThatKeepsAskingStopsAtTheLimit(t *testing.T) {
	a := hostileAPI(t, func(int) string { return `{"type":"question","content":"cQ=="}` + "\n" })
	msgs := converseThroughHost(t, a, []byte("x"))
	asked := 0
	for _, m := range msgs {
		if m.Type == envelope.TypeInputRequired {
			asked++
		}
	}
	last := msgs[len(msgs)-1]
	if asked != adapter.MaxQuestions || last.Type != envelope.TypeError || last.Content != bot.TextFailed {
		t.Fatalf("%d questions, then %v %q", asked, last.Type, last.Content)
	}
}

// Lines after the bot's final message change nothing: the first final message is the one the caller gets.
func TestHostileBotCannotAddAFinalMessageAfterItsFirst(t *testing.T) {
	out := `{"type":"result","content":"aGk="}` + "\n" + `{"type":"error","message":"` + canary + `"}` + "\n" + canary + "\n"
	for name, b := range map[string]bot.Bot{
		"API": hostileAPI(t, func(int) string { return out }),
		"CLI": cli(t, "emit", "PARLEY_OUT="+out, "PARLEY_N=1"),
	} {
		t.Run(name, func(t *testing.T) {
			msgs := converseThroughHost(t, b, []byte("x"))
			if len(msgs) != 1 || msgs[0].Type != envelope.TypeResult || msgs[0].Content != "hi" {
				t.Fatalf("%+v", msgs)
			}
		})
	}
}

// An error the bot declared is the one text of its own that reaches the caller, and only up to the cut and as valid UTF-8.
func TestHostileDeclaredErrorIsCutAndValid(t *testing.T) {
	big := `{"type":"error","message":"` + strings.Repeat("é", 100000) + `"}` + "\n"
	for name, b := range map[string]bot.Bot{
		"API": hostileAPI(t, func(int) string { return big }),
		"CLI": cli(t, "bigerror"),
	} {
		t.Run(name, func(t *testing.T) {
			msgs := converseThroughHost(t, b, []byte("x"))
			m := msgs[len(msgs)-1]
			if len(msgs) != 1 || m.Type != envelope.TypeError || len(m.Content) == 0 || len(m.Content) > bot.MaxFailure || !utf8.ValidString(m.Content) {
				t.Fatalf("%d messages, %v of %d bytes, valid %v", len(msgs), m.Type, len(m.Content), utf8.ValidString(m.Content))
			}
		})
	}
}

// Fields of a task that try to break out of their place in the line: every one arrives as exactly one line of valid
// UTF-8 with no raw control character, and decodes to the type "task" with nothing added.
func TestHostileTaskFieldsReachTheBotAsOneWellFormedLine(t *testing.T) {
	evil := []string{
		"a\"b", "line1\nline2", "\r\n", "x\x00y", "\x1b[31m", `{"type":"cancel"}`, `","type":"cancel","extra":"`, `\`, "\xff\xfe", "  ",
		"ünï", "\t", strings.Repeat("z", 64<<10), "",
	}
	taskWith := func(s string) bot.Task {
		tk := task
		tk.Context, tk.Caller, tk.Owner = s, s, s
		tk.Content = []byte("\n{\"type\":\"cancel\"}\n\x00" + s)
		return tk
	}
	check := func(t *testing.T, tk bot.Task, raw []byte) {
		t.Helper()
		if len(raw) == 0 || raw[len(raw)-1] != '\n' || !utf8.Valid(raw) {
			t.Fatalf("not a line of UTF-8: %q", raw[:min(len(raw), 80)])
		}
		for _, c := range raw[:len(raw)-1] {
			if c < 0x20 || c == 0x7f {
				t.Fatalf("a raw control byte %#x in the line", c)
			}
		}
		var in struct {
			adaptertest.InLine
			V int `json:"v"`
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil || dec.More() || in.V != 1 || in.Type != "task" {
			t.Fatalf("decoded as %+v: %v", in, err)
		}
		if !bytes.Equal(in.Content, tk.Content) {
			t.Fatal("the content did not survive as base64")
		}
		if utf8.ValidString(tk.Context) && (in.Context != tk.Context || in.Caller != tk.Caller || in.Owner != tk.Owner) {
			t.Fatal("a field changed on the way")
		}
	}
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		line, _ := bufio.NewReaderSize(r.Body, 1<<22).ReadBytes('\n')
		fmt.Fprintf(w, `{"type":"result","content":"%s"}`+"\n", base64.StdEncoding.EncodeToString(line))
	})
	for i, s := range evil {
		tk := taskWith(s)
		t.Run(fmt.Sprint("API/", i), func(t *testing.T) {
			raw, err := api(t, srv.URL, "").Handle(context.Background(), tk, &stub{})
			if err != nil {
				t.Fatal(err)
			}
			check(t, tk, raw)
		})
		t.Run(fmt.Sprint("CLI/", i), func(t *testing.T) {
			raw, err := cli(t, "firstline").Handle(context.Background(), tk, &stub{})
			if err != nil {
				t.Fatal(err)
			}
			check(t, tk, raw)
		})
	}
}

// A bot that takes the task and never answers (a child that does not read, a service that holds the request open) is
// ended at the host's limit with the fixed error, and its child process, reader and request are gone with it. The limit
// is real time, kept short here; the wait for it is generous, so a slow machine only takes longer.
func TestHostileStalledBotIsEndedAtTheLimitAndLeavesNothing(t *testing.T) {
	hold := make(chan struct{})
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		bufio.NewReaderSize(r.Body, 1<<22).ReadBytes('\n') // take the task, as a bot would
		select {
		case <-hold:
		case <-r.Context().Done():
		}
	})
	t.Cleanup(func() { close(hold) }) // after serve, so it runs before the server's Close waits for this handler
	for name, b := range map[string]bot.Bot{
		"API": api(t, srv.URL, ""),
		"CLI": cli(t, "deaf"),
	} {
		t.Run(name, func(t *testing.T) {
			msgs := converseWithin(t, b, []byte("x"), time.Second)
			last := msgs[len(msgs)-1]
			if len(msgs) != 1 || last.Type != envelope.TypeError || len(last.Content) == 0 || len(last.Content) > bot.MaxFailure || strings.Contains(last.Content, canary) {
				t.Fatalf("%+v", msgs)
			}
		})
	}
}
