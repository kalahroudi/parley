// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunAnswersOneTask(t *testing.T) {
	var out bytes.Buffer
	in := `{"v":1,"type":"task","id":"` + strings.Repeat("0", 32) + `","content":"K0RFQlVH"}` + "\n"
	if code := run(strings.NewReader(in), &out); code != 0 || !strings.HasPrefix(out.String(), `{"type":"result"`) {
		t.Fatalf("code=%d out=%q", code, out.String())
	}
}

type brokenPipe struct{}

func (brokenPipe) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestRunFailsWhenTheAnswerCannotBeWritten(t *testing.T) {
	if code := run(strings.NewReader("x\n"), brokenPipe{}); code != 1 {
		t.Fatalf("code=%d", code)
	}
}
