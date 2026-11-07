// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kalahroudi/parley/internal/fsowner"
)

// ownerFake answers for an install directory with two programs and ordinary parents; edit overrides single paths.
type ownerFake struct {
	dir   string
	edit  map[string]fsowner.Info
	fails map[string]bool
}

func (f ownerFake) inspect(p string) (fsowner.Info, error) {
	if f.fails[p] {
		return fsowner.Info{}, errors.New("cannot inspect")
	}
	if i, ok := f.edit[p]; ok {
		return i, nil
	}
	switch {
	case filepath.Dir(p) == f.dir:
		return fsowner.Info{IsRegular: true, Owned: true}, nil
	default:
		return fsowner.Info{IsDir: true, Owned: true}, nil
	}
}

func newOwnerFake(t *testing.T) (ownerFake, []string) {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return ownerFake{dir: d, edit: map[string]fsowner.Info{}, fails: map[string]bool{}},
		[]string{filepath.Join(d, "parleyd"), filepath.Join(d, "parley-cli")}
}

func TestCheckInstallDecisions(t *testing.T) {
	parent := func(f ownerFake) string { return filepath.Dir(f.dir) }
	cases := []struct {
		name string
		edit func(f ownerFake, files []string)
		want error // nil: allowed
	}{
		{"all ours", func(ownerFake, []string) {}, nil},
		{"directory owned by someone else", func(f ownerFake, _ []string) { f.edit[f.dir] = fsowner.Info{IsDir: true} }, ErrNotOwner},
		{"directory writable by group or others", func(f ownerFake, _ []string) {
			f.edit[f.dir] = fsowner.Info{IsDir: true, Owned: true, GroupOrOtherWrite: true}
		}, ErrNotOwner},
		{"install path is not a directory", func(f ownerFake, _ []string) { f.edit[f.dir] = fsowner.Info{Owned: true, IsRegular: true} }, ErrNotOwner},
		{"parent owned by someone else", func(f ownerFake, _ []string) { f.edit[parent(f)] = fsowner.Info{IsDir: true} }, ErrNotOwner},
		{"parent owned by the system", func(f ownerFake, _ []string) { f.edit[parent(f)] = fsowner.Info{IsDir: true, Trusted: true} }, nil},
		{"parent writable by everyone", func(f ownerFake, _ []string) {
			f.edit[parent(f)] = fsowner.Info{IsDir: true, Owned: true, WorldWrite: true}
		}, ErrNotOwner},
		{"parent writable by everyone with the sticky bit", func(f ownerFake, _ []string) {
			f.edit[parent(f)] = fsowner.Info{IsDir: true, Trusted: true, WorldWrite: true, Sticky: true}
		}, nil},
		{"parent writable by a group", func(f ownerFake, _ []string) {
			f.edit[parent(f)] = fsowner.Info{IsDir: true, Owned: true, GroupOrOtherWrite: true}
		}, ErrNotOwner},
		{"parent writable by a group and owned by the system", func(f ownerFake, _ []string) {
			f.edit[parent(f)] = fsowner.Info{IsDir: true, Trusted: true, GroupOrOtherWrite: true}
		}, nil},
		{"parent writable by a group with the sticky bit", func(f ownerFake, _ []string) {
			f.edit[parent(f)] = fsowner.Info{IsDir: true, Owned: true, GroupOrOtherWrite: true, Sticky: true}
		}, nil},
		{"program is setuid or setgid", func(f ownerFake, files []string) {
			f.edit[files[0]] = fsowner.Info{IsRegular: true, Owned: true, Setid: true}
		}, ErrNotOwner},
		{"a distant parent owned by someone else", func(f ownerFake, _ []string) {
			f.edit[filepath.Dir(parent(f))] = fsowner.Info{IsDir: true}
		}, ErrNotOwner},
		{"the root of the tree is checked too", func(f ownerFake, _ []string) {
			root := f.dir
			for filepath.Dir(root) != root {
				root = filepath.Dir(root)
			}
			f.edit[root] = fsowner.Info{IsDir: true, WorldWrite: true}
		}, ErrNotOwner},
		{"program is a link or special file", func(f ownerFake, files []string) { f.edit[files[0]] = fsowner.Info{Owned: true} }, ErrNotOwner},
		{"program owned by someone else", func(f ownerFake, files []string) { f.edit[files[1]] = fsowner.Info{IsRegular: true} }, ErrNotOwner},
		{"program writable by group or others", func(f ownerFake, files []string) {
			f.edit[files[1]] = fsowner.Info{IsRegular: true, Owned: true, GroupOrOtherWrite: true}
		}, ErrNotOwner},
	}
	for _, c := range cases {
		f, files := newOwnerFake(t)
		c.edit(f, files)
		err := checkInstall(f.dir, files, f.inspect)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestCheckInstallInspectErrors(t *testing.T) {
	for name, pick := range map[string]func(f ownerFake, files []string) string{
		"directory": func(f ownerFake, _ []string) string { return f.dir },
		"parent":    func(f ownerFake, _ []string) string { return filepath.Dir(f.dir) },
		"program":   func(_ ownerFake, files []string) string { return files[0] },
	} {
		f, files := newOwnerFake(t)
		f.fails[pick(f, files)] = true
		if err := checkInstall(f.dir, files, f.inspect); err == nil || errors.Is(err, ErrNotOwner) {
			t.Errorf("%s: got %v, want the inspection error", name, err)
		}
	}
	if err := checkInstall(filepath.Join(t.TempDir(), "missing"), nil, nil); err == nil {
		t.Error("a missing directory was accepted")
	}
}

// Apply stops before it downloads or writes anything when the owner check fails.
func TestApplyRefusesBeforeDownloadingWhenNotOwner(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	u := r.updater("v1.0.0", "")
	rel, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	asked := len(r.src.asked)
	u.inspect = func(string) (fsowner.Info, error) { return fsowner.Info{IsDir: true, IsRegular: true}, nil } // owned by nobody we are
	if err := u.Apply(context.Background(), rel); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("got %v", err)
	}
	if len(r.src.asked) != asked {
		t.Fatal("downloaded before the owner check")
	}
	if r.read(t, "parleyd") != "old parleyd" || r.read(t, "parley-cli") != "old parley-cli" {
		t.Fatal("a program was replaced")
	}
	ents, _ := os.ReadDir(r.dir)
	if len(ents) != 2 {
		t.Fatalf("files left behind: %v", ents)
	}
	// Update goes through the same gate.
	if _, err := u.Update(context.Background()); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("Update: got %v", err)
	}
}

// With the real operating system's answers: a directory the test just made is ours and passes.
func TestRealInstallDirectoryOfOursPasses(t *testing.T) {
	r := newRelease(t)
	if runtime.GOOS != "windows" {
		os.Chmod(r.dir, 0o700)
	}
	u := r.updater("v1.0.0", "")
	if names, _, err := u.checkOwner(); err != nil || len(names) != 2 {
		t.Fatalf("%v %v", names, err)
	}
	// A missing first program is an error of its own, not an ownership one.
	os.Remove(filepath.Join(r.dir, "parleyd"+exeSuffix(runtime.GOOS)))
	if _, _, err := u.checkOwner(); err == nil || errors.Is(err, ErrNotOwner) {
		t.Fatalf("got %v", err)
	}
}

// A directory a package manager owns is refused with the pointer to the right channel, before anything else.
func TestApplyRefusesPackageManagerDirectory(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	u := r.updater("v1.0.0", "")
	rel, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cellar := filepath.Join(t.TempDir(), "Cellar", "parley")
	if err := os.MkdirAll(cellar, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"parleyd", "parley-cli"} {
		os.WriteFile(filepath.Join(cellar, n+exeSuffix(runtime.GOOS)), []byte("old"), 0o700)
	}
	u.Dir = cellar
	asked := len(r.src.asked)
	if err := u.Apply(context.Background(), rel); !errors.Is(err, ErrManaged) {
		t.Fatalf("got %v", err)
	}
	if len(r.src.asked) != asked {
		t.Fatal("downloaded for a managed directory")
	}
}

// watchSource runs hook before every download, which is where an attacker with time gets to act.
type watchSource struct {
	Source
	hook func()
}

func (w watchSource) Fetch(ctx context.Context, version, name string, limit int64, out io.Writer) error {
	w.hook()
	return w.Source.Fetch(ctx, version, name, limit, out)
}

// The owner check is repeated right before the swap: if the install stops passing while the downloads run,
// nothing is replaced and nothing is left behind (on every OS, with the inspection faked).
func TestApplyChecksAgainBeforeSwapping(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	u := r.updater("v1.0.0", "")
	rel, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	foreign := false
	u.inspect = func(p string) (fsowner.Info, error) {
		if foreign && filepath.Base(p) == "parleyd"+exeSuffix(runtime.GOOS) {
			return fsowner.Info{IsRegular: true}, nil // now somebody else's
		}
		if b := filepath.Base(p); b == "parleyd"+exeSuffix(runtime.GOOS) || b == "parley-cli"+exeSuffix(runtime.GOOS) {
			return fsowner.Info{IsRegular: true, Owned: true}, nil
		}
		return fsowner.Info{IsDir: true, Owned: true}, nil
	}
	u.Source = watchSource{u.Source, func() { foreign = true }}
	if err := u.Apply(context.Background(), rel); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("got %v", err)
	}
	if r.read(t, "parleyd") != "old parleyd" || r.read(t, "parley-cli") != "old parley-cli" {
		t.Fatal("a program was replaced")
	}
	if ents, _ := os.ReadDir(r.dir); len(ents) != 2 {
		t.Fatalf("files left behind: %v", ents)
	}
}

// A directory that does not exist is an error of its own, before anything is inspected or downloaded.
func TestApplyMissingDirectory(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	u := r.updater("v1.0.0", "")
	rel, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u.Dir = filepath.Join(t.TempDir(), "missing")
	if err := u.Apply(context.Background(), rel); err == nil || errors.Is(err, ErrNotOwner) {
		t.Fatalf("got %v", err)
	}
}
