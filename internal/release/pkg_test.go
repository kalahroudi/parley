// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeRelease writes release-named binaries for every target of tag into a new directory.
func fakeRelease(t *testing.T, tag string) string {
	t.Helper()
	d := t.TempDir()
	for _, goos := range []string{"darwin", "linux"} {
		for _, arch := range []string{"amd64", "arm64"} {
			for _, cmd := range []string{"parleyd", "parley-cli"} {
				if err := os.WriteFile(filepath.Join(d, cmd+"_"+tag+"_"+goos+"_"+arch), []byte(cmd+goos+arch), 0o755); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return d
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestFormula(t *testing.T) {
	d := fakeRelease(t, "v1.2.3")
	out, err := Formula("v1.2.3", d)
	if err != nil {
		t.Fatal(err)
	}
	f := string(out)
	for _, want := range []string{
		`version "1.2.3"`, `license "Apache-2.0"`, "on_macos do", "on_linux do", "on_arm do", "on_intel do",
		`url "https://github.com/kalahroudi/parley/releases/download/v1.2.3/parleyd_v1.2.3_darwin_arm64"`,
		`sha256 "` + sha("parleydlinuxamd64") + `"`,
		`sha256 "` + sha("parley-clidarwinarm64") + `"`,
		`resource "parley-cli" do`, `shell_output("#{bin}/parleyd --version")`,
	} {
		if !strings.Contains(f, want) {
			t.Errorf("formula lacks %q", want)
		}
	}
	// Each platform block names its own files and hashes, not another platform's.
	for _, p := range []struct{ goos, arch string }{{"darwin", "arm64"}, {"darwin", "amd64"}, {"linux", "arm64"}, {"linux", "amd64"}} {
		for _, cmd := range []string{"parleyd", "parley-cli"} {
			if !strings.Contains(f, cmd+"_v1.2.3_"+p.goos+"_"+p.arch+`"`+"\n"+"      sha256 \""+sha(cmd+p.goos+p.arch)+`"`) &&
				!strings.Contains(f, cmd+"_v1.2.3_"+p.goos+"_"+p.arch+`"`+"\n"+"        sha256 \""+sha(cmd+p.goos+p.arch)+`"`) {
				t.Errorf("%s %s/%s: url and hash do not go together", cmd, p.goos, p.arch)
			}
		}
	}
	again, _ := Formula("v1.2.3", d)
	if !bytes.Equal(out, again) {
		t.Fatal("not deterministic")
	}
	if ruby, err := exec.LookPath("ruby"); err == nil {
		p := filepath.Join(t.TempDir(), "parley.rb")
		os.WriteFile(p, out, 0o644)
		if b, err := exec.Command(ruby, "-c", p).CombinedOutput(); err != nil {
			t.Fatalf("ruby -c: %v %s", err, b)
		}
	}
	for _, tag := range []string{"1.2.3", "v1.2", "v1.2.3-rc1", "v01.2.3", "v1.2.x", "v1..3", "", "vv1.2.3", "v1.2.1234567890"} {
		if _, err := Formula(tag, d); err == nil {
			t.Errorf("tag %q accepted", tag)
		}
	}
	if _, err := Formula("v9.9.9", d); err == nil {
		t.Fatal("missing binaries accepted")
	}
	os.Remove(filepath.Join(d, "parley-cli_v1.2.3_linux_arm64"))
	if _, err := Formula("v1.2.3", d); err == nil {
		t.Fatal("missing parley-cli accepted")
	}
}

// arMembers parses a Debian archive into its members.
func arMembers(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	if !bytes.HasPrefix(b, []byte("!<arch>\n")) {
		t.Fatal("no ar magic")
	}
	b = b[8:]
	out := map[string][]byte{}
	for len(b) > 0 {
		if len(b) < 60 || string(b[58:60]) != "`\n" {
			t.Fatal("bad ar header")
		}
		name := strings.TrimSpace(string(b[:16]))
		n, err := strconv.Atoi(strings.TrimSpace(string(b[48:58])))
		if err != nil || len(b) < 60+n {
			t.Fatal("bad ar size")
		}
		out[name] = b[60 : 60+n]
		b = b[60+n:]
		if n%2 == 1 {
			if len(b) == 0 || b[0] != '\n' {
				t.Fatal("missing padding")
			}
			b = b[1:]
		}
	}
	return out
}

type entry struct {
	mode  int64
	owner string
	mtime time.Time
	data  string
	dir   bool
}

func untar(t *testing.T, gz []byte) map[string]entry {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	if !zr.ModTime.IsZero() {
		t.Fatal("gzip header carries a time")
	}
	tr := tar.NewReader(zr)
	out := map[string]entry{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = entry{h.Mode, h.Uname + ":" + h.Gname, h.ModTime, string(b), h.Typeflag == tar.TypeDir}
	}
}

func TestBuildDeb(t *testing.T) {
	d := fakeRelease(t, "v1.2.3")
	deb, err := BuildDeb("v1.2.3", "arm64", d)
	if err != nil {
		t.Fatal(err)
	}
	m := arMembers(t, deb)
	if string(m["debian-binary"]) != "2.0\n" || len(m) != 3 {
		t.Fatalf("members: %v", m)
	}
	c := untar(t, m["control.tar.gz"])["./control"].data
	for _, want := range []string{"Package: parley\n", "Version: 1.2.3\n", "Architecture: arm64\n", "Installed-Size: 1\n", "Homepage: https://github.com/kalahroudi/parley\n"} {
		if !strings.Contains(c, want) {
			t.Errorf("control lacks %q:\n%s", want, c)
		}
	}
	data := untar(t, m["data.tar.gz"])
	if len(data) != 4 || !data["./usr/"].dir || !data["./usr/bin/"].dir {
		t.Fatalf("data: %v", data)
	}
	if e := data["./usr/bin/parleyd"]; e.data != "parleydlinuxarm64" || e.mode != 0o755 || e.owner != "root:root" || !e.mtime.Equal(debEpoch) {
		t.Fatalf("parleyd: %+v", e)
	}
	if e := data["./usr/bin/parley-cli"]; e.data != "parley-clilinuxarm64" || e.mode != 0o755 {
		t.Fatalf("parley-cli: %+v", e)
	}
	again, _ := BuildDeb("v1.2.3", "arm64", d)
	if !bytes.Equal(deb, again) {
		t.Fatal("not deterministic")
	}
	// An odd-sized member is padded.
	var odd bytes.Buffer
	odd.WriteString("!<arch>\n")
	arMember(&odd, "x", []byte("abc"))
	if got := arMembers(t, odd.Bytes())["x"]; string(got) != "abc" {
		t.Fatalf("padding: %q", got)
	}
	// The real dpkg tooling accepts it when it is installed (CI on Linux has it).
	if dpkg, err := exec.LookPath("dpkg-deb"); err == nil {
		p := filepath.Join(t.TempDir(), "parley_1.2.3_arm64.deb")
		os.WriteFile(p, deb, 0o644)
		if b, err := exec.Command(dpkg, "--info", p).CombinedOutput(); err != nil || !strings.Contains(string(b), "Package: parley") {
			t.Fatalf("dpkg-deb --info: %v %s", err, b)
		}
		if b, err := exec.Command(dpkg, "--contents", p).CombinedOutput(); err != nil || !strings.Contains(string(b), "./usr/bin/parleyd") {
			t.Fatalf("dpkg-deb --contents: %v %s", err, b)
		}
	}
	if _, err := BuildDeb("v1.2", "arm64", d); err == nil {
		t.Fatal("bad tag accepted")
	}
	if _, err := BuildDeb("v1.2.3", "riscv64", d); err == nil {
		t.Fatal("unsupported architecture accepted")
	}
	if _, err := BuildDeb("v1.2.3", "amd64", t.TempDir()); err == nil {
		t.Fatal("missing binaries accepted")
	}
	os.Remove(filepath.Join(d, "parley-cli_v1.2.3_linux_amd64"))
	if _, err := BuildDeb("v1.2.3", "amd64", d); err == nil {
		t.Fatal("missing parley-cli accepted")
	}
}

func TestDebControlOmitsUnknownSize(t *testing.T) {
	if strings.Contains(debControl("1.0.0", "amd64", 0), "Installed-Size") || !strings.Contains(debControl("1.0.0", "amd64", 5), "Installed-Size: 5\n") {
		t.Fatal("Installed-Size")
	}
}

func TestAptIndex(t *testing.T) {
	d := t.TempDir()
	if _, _, err := AptIndex(d, time.Now()); err == nil {
		t.Fatal("empty repository accepted")
	}
	if _, _, err := AptIndex(filepath.Join(d, "nope"), time.Now()); err == nil {
		t.Fatal("missing directory accepted")
	}
	files := map[string]string{
		"parley_1.2.3_amd64.deb": "one", "parley_1.2.3_arm64.deb": "two", "parley_1.10.0_amd64.deb": "three",
		"parley_1.2.3_i386.deb": "ignored", "other.txt": "ignored", "parley_v1.2.3_amd64.deb": "ignored",
	}
	for n, b := range files {
		os.WriteFile(filepath.Join(d, n), []byte(b), 0o644)
	}
	os.Mkdir(filepath.Join(d, "parley_9.9.9_amd64.deb"), 0o755) // a directory by that name cannot be read
	if _, _, err := AptIndex(d, time.Now()); err == nil {
		t.Fatal("unreadable entry accepted")
	}
	os.Remove(filepath.Join(d, "parley_9.9.9_amd64.deb"))
	date := time.Date(2026, 11, 7, 12, 30, 0, 0, time.UTC)
	pk, rel, err := AptIndex(d, date)
	if err != nil {
		t.Fatal(err)
	}
	p := string(pk)
	for _, want := range []string{
		"Package: parley\nVersion: 1.2.3\nArchitecture: amd64\n", "Version: 1.10.0\n", "Architecture: arm64\n",
		"Filename: ./parley_1.2.3_arm64.deb\nSize: 3\nSHA256: " + sha("two") + "\n",
		"SHA256: " + sha("three") + "\n\n",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("Packages lacks %q:\n%s", want, p)
		}
	}
	if strings.Contains(p, "ignored") || strings.Contains(p, "i386") || strings.Contains(p, "Installed-Size") || strings.Count(p, "Package: parley") != 3 {
		t.Fatalf("Packages: %s", p)
	}
	// Versions are listed in file name order: 1.10.0 before 1.2.3 as strings, which apt does not mind (it sorts).
	r := string(rel)
	for _, want := range []string{"Date: Sat, 07 Nov 2026 12:30:00 UTC\n", "Architectures: amd64 arm64\n", " " + sha(p) + " " + strconv.Itoa(len(p)) + " Packages\n", "Suite: stable\n", "Components: main\n"} {
		if !strings.Contains(r, want) {
			t.Errorf("Release lacks %q:\n%s", want, r)
		}
	}
	pk2, rel2, _ := AptIndex(d, date)
	if !bytes.Equal(pk, pk2) || !bytes.Equal(rel, rel2) {
		t.Fatal("not deterministic")
	}
	// Package files really built by BuildDeb are indexed with their true size and hash.
	real := fakeRelease(t, "v2.0.0")
	deb, _ := BuildDeb("v2.0.0", "amd64", real)
	rd := t.TempDir()
	os.WriteFile(filepath.Join(rd, "parley_2.0.0_amd64.deb"), deb, 0o644)
	pk3, _, _ := AptIndex(rd, date)
	if !strings.Contains(string(pk3), "Size: "+strconv.Itoa(len(deb))+"\nSHA256: "+sha(string(deb))+"\n") {
		t.Fatalf("real package: %s", pk3)
	}
}
