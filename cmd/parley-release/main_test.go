// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeygenSignVerifyAndNoOverwrite(t *testing.T) {
	d := t.TempDir()
	if err := run([]string{"keygen", filepath.Join(d, "n"), filepath.Join(d, "n.pub")}); err == nil {
		t.Fatal("keygen without a password accepted")
	}
	t.Setenv(passwordEnv, "test-password")
	sk, pk := filepath.Join(d, "k"), filepath.Join(d, "k.pub")
	if err := run([]string{"keygen", sk, pk}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", sk, filepath.Join(d, "x.pub")}); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	f := filepath.Join(d, "f")
	os.WriteFile(f, []byte("data"), 0o644)
	if err := run([]string{"sign", sk, f, "c"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", pk, f}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", sk, f, "a\nb"}); err == nil {
		t.Fatal("multi-line comment accepted")
	}
	if err := run([]string{"bogus"}); err == nil {
		t.Fatal("unknown command accepted")
	}
}
