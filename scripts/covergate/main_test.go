// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const src = `package p

func a() int {
	return 1
}

//cover:ignore unreachable on this platform
func b() int {
	return 2
}

func c(err error) int {
	//cover:ignore rand never fails
	if err != nil {
		return 3
	}
	return 4
}
`

// A fixture module: p.go has four blocks (lines 4, 9, 15 and 17).
func fixture(t *testing.T, tiers, profile string, files map[string]string) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("go.mod", "module example.test/m\n\ngo 1.24\n")
	for n, d := range files {
		write(n, d)
	}
	return root, write("tiers.json", tiers), write("cover.out", profile)
}

func gate(root, cfg, prof string) (int, string, string) {
	var out, errw bytes.Buffer
	code := run(prof, cfg, root, &out, &errw)
	return code, out.String(), errw.String()
}

const header = "mode: atomic\n"

func TestPassAndExclusions(t *testing.T) {
	tiers := `{"tiers":{"2":{"line":95,"packages":["p"]}}}`
	// b's block and the ignored if body are uncovered but excluded.
	prof := header + "example.test/m/p/p.go:4.2,4.10 1 1\nexample.test/m/p/p.go:9.2,9.10 1 0\nexample.test/m/p/p.go:15.3,15.11 1 0\nexample.test/m/p/p.go:17.2,17.10 1 3\n"
	root, cfg, p := fixture(t, tiers, prof, map[string]string{"p/p.go": src})
	code, out, errw := gate(root, cfg, p)
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, out, errw)
	}
	if strings.Contains(out, "not covered") {
		t.Errorf("a passing package lists statements:\n%s", out)
	}
	for _, want := range []string{"100.0%", "2/2 statements", "unreachable on this platform", "rand never fails", "p.go:7", "p.go:13"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestBelowGateFails(t *testing.T) {
	tiers := `{"tiers":{"2":{"line":95,"packages":["p"]}}}`
	prof := header + "example.test/m/p/p.go:4.2,4.10 1 1\nexample.test/m/p/p.go:9.2,9.10 1 0\nexample.test/m/p/p.go:15.3,15.11 1 0\nexample.test/m/p/p.go:17.2,17.10 1 3\n"
	// the same profile with no exclusions in the source
	plain := strings.NewReplacer("//cover:ignore", "// note").Replace(src)
	root, cfg, p := fixture(t, tiers, prof, map[string]string{"p/p.go": plain})
	code, out, _ := gate(root, cfg, p)
	if code != 1 || !strings.Contains(out, "FAIL tier 2") || !strings.Contains(out, "50.0%") {
		t.Fatalf("code %d\n%s", code, out)
	}
	if !strings.Contains(out, "     not covered: p/p.go:9-9 (1 statements)\n     not covered: p/p.go:15-15 (1 statements)\n") {
		t.Fatalf("the missed statements are not listed:\n%s", out)
	}
}

// The missed statements come out sorted by file, then line, whatever order the profile has them in.
func TestMissedStatementsAreListedInOrder(t *testing.T) {
	tiers := `{"tiers":{"1":{"line":100,"packages":["p"]}}}`
	prof := header + "example.test/m/p/q.go:3.2,3.10 2 0\nexample.test/m/p/p.go:15.3,15.11 1 0\nexample.test/m/p/p.go:4.2,4.10 1 1\nexample.test/m/p/p.go:9.2,9.10 1 0\n"
	plain := strings.NewReplacer("//cover:ignore", "// note").Replace(src)
	root, cfg, p := fixture(t, tiers, prof, map[string]string{"p/p.go": plain, "p/q.go": "package p\n\nfunc q() {\n\t_ = 1\n\t_ = 2\n}\n"})
	code, out, _ := gate(root, cfg, p)
	want := "     not covered: p/p.go:9-9 (1 statements)\n     not covered: p/p.go:15-15 (1 statements)\n     not covered: p/q.go:3-3 (2 statements)\n"
	if code != 1 || !strings.Contains(out, want) {
		t.Fatalf("code %d\n%s", code, out)
	}
}

func TestTierOneForbidsExclusions(t *testing.T) {
	tiers := `{"tiers":{"1":{"line":100,"packages":["p"]}}}`
	prof := header + "example.test/m/p/p.go:4.2,4.10 1 1\nexample.test/m/p/p.go:9.2,9.10 1 0\n"
	root, cfg, p := fixture(t, tiers, prof, map[string]string{"p/p.go": src})
	code, _, errw := gate(root, cfg, p)
	if code != 1 || !strings.Contains(errw, "tier 1 allows no coverage exclusions") {
		t.Fatalf("code %d\n%s", code, errw)
	}
}

func TestPackagesMustBeClassifiedAndPresent(t *testing.T) {
	tiers := `{"tiers":{"2":{"line":95,"packages":["gone"]}}}`
	prof := header + "example.test/m/p/p.go:4.2,4.10 1 1\n"
	root, cfg, p := fixture(t, tiers, prof, map[string]string{"p/p.go": "package p\n\nfunc a() int {\n\treturn 1\n}\n"})
	code, _, errw := gate(root, cfg, p)
	if code != 1 || !strings.Contains(errw, "p has statements but is in no coverage tier") || !strings.Contains(errw, "gone is not in the profile") {
		t.Fatalf("code %d\n%s", code, errw)
	}
}

func TestEmptyPackageCountsAsFull(t *testing.T) {
	// every statement excluded: nothing left to cover
	tiers := `{"tiers":{"2":{"line":95,"packages":["p"]}}}`
	prof := header + "example.test/m/p/p.go:9.2,9.10 1 0\n"
	root, cfg, p := fixture(t, tiers, prof, map[string]string{"p/p.go": src})
	if code, out, errw := gate(root, cfg, p); code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, out, errw)
	}
}

func TestBadInputs(t *testing.T) {
	ok := `{"tiers":{"2":{"line":95,"packages":["p"]}}}`
	good := header + "example.test/m/p/p.go:4.2,4.10 1 1\n"
	file := map[string]string{"p/p.go": "package p\n\nfunc a() int {\n\treturn 1\n}\n"}
	for name, tc := range map[string]struct {
		tiers, prof, gomod string
		files              map[string]string
	}{
		"bad config":     {`{"tiers":1}`, good, "", file},
		"unknown field":  {`{"x":1}`, good, "", file},
		"bad profile":    {ok, "mode: set\nnonsense\n", "", file},
		"bad span":       {ok, header + "f.go:1 1 1\n", "", file},
		"bad numbers":    {ok, header + "example.test/m/p/p.go:x.1,2.1 1 1\n", "", file},
		"no module":      {ok, good, "go 1.24\n", file},
		"unparsable src": {ok, good, "", map[string]string{"p/p.go": "package"}},
		"no reason":      {ok, good, "", map[string]string{"p/p.go": "package p\n\n//cover:ignore\nfunc a() {}\n"}},
		"dangling":       {ok, good, "", map[string]string{"p/p.go": "package p\n\n//cover:ignore reason\n\nfunc a() {}\n"}},
	} {
		root, cfg, p := fixture(t, tc.tiers, tc.prof, tc.files)
		if tc.gomod != "" {
			os.WriteFile(filepath.Join(root, "go.mod"), []byte(tc.gomod), 0o644)
		}
		if code, _, errw := gate(root, cfg, p); code != 2 || errw == "" {
			t.Errorf("%s: code %d %q", name, code, errw)
		}
	}
	root, cfg, p := fixture(t, ok, good, file)
	for name, args := range map[string][3]string{
		"missing config":  {p, filepath.Join(root, "none.json"), root},
		"missing profile": {filepath.Join(root, "none.out"), cfg, root},
		"missing go.mod":  {p, cfg, filepath.Join(root, "sub")},
	} {
		var out, errw bytes.Buffer
		if code := run(args[0], args[1], args[2], &out, &errw); code != 2 {
			t.Errorf("%s: code %d", name, code)
		}
	}
}
