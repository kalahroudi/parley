// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package prekey

import (
	"errors"
	"testing"
)

func TestHarden(t *testing.T) {
	if err := Harden(); err != nil {
		t.Fatal(err)
	}
}

func TestRunStepsStopsAtFirstFailure(t *testing.T) {
	boom := errors.New("boom")
	ran := 0
	step := func(err error) func() error { return func() error { ran++; return err } }
	if err := runSteps(step(nil), step(boom), step(nil)); !errors.Is(err, boom) || ran != 2 {
		t.Fatalf("err %v ran %d", err, ran)
	}
	if err := runSteps(); err != nil {
		t.Fatal(err)
	}
}
