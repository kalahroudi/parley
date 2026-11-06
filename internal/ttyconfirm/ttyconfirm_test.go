// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package ttyconfirm

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const childEnv = "PARLEY_TTYCONFIRM_CHILD"

// TestMain lets the test binary be the process that asks: a child run with childEnv set calls Ask and prints the result.
func TestMain(m *testing.M) {
	if os.Getenv(childEnv) != "" {
		ok, err := Ask("question? ")
		switch {
		case err != nil:
			fmt.Printf("RESULT:error:%v\n", err)
		case ok:
			fmt.Println("RESULT:yes")
		default:
			fmt.Println("RESULT:no")
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type rw struct {
	io.Reader
	io.Writer
}

func TestAskOnAcceptsOnlyAnExplicitYes(t *testing.T) {
	for in, want := range map[string]bool{
		"y\n": true, "yes\n": true, "YES\r\n": true, " Yes \n": true, "yes": true,
		"": false, "\n": false, "n\n": false, "no\n": false, "yess\n": false, "yes please\n": false, "ye\n": false,
		strings.Repeat("y", 100) + "\n": false, "\x00yes\n": false,
	} {
		var out bytes.Buffer
		got, err := AskOn(rw{strings.NewReader(in), &out}, "go? ")
		if err != nil || got != want || out.String() != "go? " {
			t.Errorf("%q: got %v %v (printed %q), want %v", in, got, err, out.String(), want)
		}
	}
}

func TestAskOnReadsNoMoreThanTheLimit(t *testing.T) {
	r := &countReader{}
	AskOn(rw{r, io.Discard}, "")
	if r.n > maxAnswer {
		t.Errorf("read %d bytes of an answer limited to %d", r.n, maxAnswer)
	}
}

type countReader struct{ n int }

func (c *countReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'y'
	}
	c.n += len(p)
	return len(p), nil
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken") }

func TestAskOnWithATerminalThatCannotBeWrittenTo(t *testing.T) {
	if ok, err := AskOn(rw{strings.NewReader("yes\n"), failWriter{}}, "q"); ok || !errors.Is(err, ErrNoTerminal) {
		t.Errorf("got %v %v", ok, err)
	}
}

func TestAskUsesTheTerminalOnly(t *testing.T) {
	old := terminal
	defer func() { terminal = old }()
	var out bytes.Buffer
	closed := false
	terminal = func() (io.ReadWriter, func(), error) {
		return rw{strings.NewReader("yes\n"), &out}, func() { closed = true }, nil
	}
	if ok, err := Ask("q? "); !ok || err != nil || !closed || out.String() != "q? " {
		t.Errorf("got %v %v closed %v printed %q", ok, err, closed, out.String())
	}
	terminal = func() (io.ReadWriter, func(), error) { return nil, nil, errors.New("no tty") }
	if ok, err := Ask("q? "); ok || !errors.Is(err, ErrNoTerminal) {
		t.Errorf("without a terminal: %v %v", ok, err)
	}
}

// ask runs the asking child with the given standard input, argument and environment, detached from any terminal.
func askDetached(t *testing.T, stdin string) string {
	t.Helper()
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "--yes", "-y", "yes")
	cmd.Env = append(os.Environ(), childEnv+"=1", "PARLEY_YES=yes", "YES=yes", "CONFIRM=yes")
	cmd.Stdin = strings.NewReader(stdin)
	detach(cmd)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		t.Fatal("the child waited for an answer it could never get")
	}
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return string(out)
}

// A process with no controlling terminal (a bot: it is started detached) cannot answer, whatever it is given on
// standard input, in its arguments or in its environment.
func TestAProcessWithoutATerminalCannotAnswer(t *testing.T) {
	out := askDetached(t, "yes\ny\nyes\n")
	if !strings.Contains(out, "RESULT:error:"+ErrNoTerminal.Error()) || strings.Contains(out, "RESULT:yes") {
		t.Fatalf("a detached process was able to ask or answer: %q", out)
	}
}
