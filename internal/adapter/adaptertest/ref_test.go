// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adaptertest_test

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/adapter/adaptertest"
	"github.com/kalahroudi/parley/internal/bot/bottest"
)

const id = "0100000000000000000000000000000a"

// lines runs script on the Fake and collects its lines until the task is over.
func lines(t *testing.T, script string) (*adaptertest.Conv, []adaptertest.OutLine) {
	t.Helper()
	c := adaptertest.Start(&bottest.Fake{}, adaptertest.InLine{ID: id, Context: "c", Caller: "d", Owner: "o",
		Expires: "2030-01-02T03:04:05Z", Content: []byte(script)})
	var got []adaptertest.OutLine
	timeout := time.After(10 * time.Second)
	for {
		select {
		case o, ok := <-c.Out:
			if !ok {
				return c, got
			}
			got = append(got, o)
			if o.Type == "question" {
				c.Answers <- []byte("blue")
			}
		case <-timeout:
			t.Fatal("the task did not end")
		}
	}
}

func TestStartRunsATaskToItsResult(t *testing.T) {
	_, got := lines(t, "status working")
	if len(got) != 2 || got[0].Type != "status" || string(got[0].Content) != "working" || got[1].Type != "result" {
		t.Fatalf("%+v", got)
	}
}

func TestStartPutsTheAnswerToTheQuestion(t *testing.T) {
	_, got := lines(t, "ask which?")
	if len(got) != 2 || got[0].Type != "question" || string(got[1].Content) != "answer: blue" {
		t.Fatalf("%+v", got)
	}
}

func TestStartMapsFailuresPanicsAndErrors(t *testing.T) {
	for script, want := range map[string]string{
		"fail no such file": "no such file",
		"leak SECRET":       "the bot failed",
		"panic SECRET":      "the bot failed",
	} {
		_, got := lines(t, script)
		if len(got) != 1 || got[0].Type != "error" || got[0].Message != want {
			t.Fatalf("%s: %+v", script, got)
		}
	}
}

func TestCancelEndsTheBotWithoutALine(t *testing.T) {
	c := adaptertest.Start(&bottest.Fake{}, adaptertest.InLine{ID: id, Content: []byte("block")})
	c.Cancel()
	select {
	case o, ok := <-c.Out:
		if ok {
			t.Fatalf("a canceled bot said %+v", o)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the bot was not canceled")
	}
}

func TestWriteLine(t *testing.T) {
	var b bytes.Buffer
	adaptertest.WriteLine(&b, adaptertest.OutLine{Type: "error", Message: "m"})
	if !strings.HasSuffix(b.String(), "\n") || !strings.Contains(b.String(), `"message":"m"`) {
		t.Fatal(b.String())
	}
}

// ServeStdio plays the line protocol over pipes: a question gets the answer line that follows the task, and the end of
// the input cancels a task that is still running.
func TestServeStdio(t *testing.T) {
	var out bytes.Buffer
	pr, pw := io.Pipe() // stays open until the task is over, as the adapter's pipe does
	defer pw.Close()
	go pw.Write([]byte(`{"type":"task","id":"` + id + `","content":"YXNrIHE="}` + "\n" + `{"type":"answer","id":"` + id + `","turn":1,"content":"Ymx1ZQ=="}` + "\n"))
	adaptertest.ServeStdio(&bottest.Fake{}, pr, &out)
	want := `{"type":"question","content":"cQ=="}` + "\n" + `{"type":"result","content":"YW5zd2VyOiBibHVl"}` + "\n"
	if out.String() != want {
		t.Fatalf("%q", out.String())
	}
	out.Reset()
	adaptertest.ServeStdio(&bottest.Fake{}, strings.NewReader(`{"type":"task","id":"`+id+`","content":"YmxvY2s="}`+"\n"), &out)
	if out.Len() != 0 {
		t.Fatalf("a canceled task wrote %q", out.String())
	}
	adaptertest.ServeStdio(&bottest.Fake{}, strings.NewReader("garbage\n"), &out)
}
