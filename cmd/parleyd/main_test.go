// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunReturnsWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRunBlocksUntilCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	select {
	case <-done:
		t.Fatal("run returned before cancel")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after cancel")
	}
}

func TestExecute(t *testing.T) {
	var out, errw bytes.Buffer
	ctx := context.Background()
	ok := func(context.Context) error { return nil }
	if code := execute(ctx, []string{"--version"}, &out, &errw, func(context.Context) error { t.Fatal("ran the daemon for --version"); return nil }); code != 0 || out.String() != "parleyd "+version+"\n" {
		t.Fatalf("--version: %d %q", code, out.String())
	}
	if code := execute(ctx, nil, &out, &errw, ok); code != 0 {
		t.Fatalf("clean run: %d", code)
	}
	errw.Reset()
	if code := execute(ctx, nil, &out, &errw, func(context.Context) error { return errors.New("boom") }); code != 1 || errw.String() != "parleyd: boom\n" {
		t.Fatalf("failing run: %d %q", code, errw.String())
	}
}
