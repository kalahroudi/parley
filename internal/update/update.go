// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kalahroudi/parley/internal/fsowner"
	"github.com/kalahroudi/parley/internal/release"
)

// Limits on what is read from an untrusted source.
const (
	maxSums   = 64 << 10
	maxSig    = 4 << 10
	maxBinary = 256 << 20
	signed    = "SHA256SUMS"
	commentIs = "parley release "
)

var (
	// ErrUpToDate means there is nothing newer to install (or, when pinned, the pinned version is installed).
	ErrUpToDate = errors.New("update: already up to date")
	// ErrNotRelease means the running binary is not a release build (a source or go install build), so it has no
	// version to compare and is never replaced.
	ErrNotRelease = errors.New("update: this is not a release build; build or install a release to get updates")
	// ErrSignature means the checksums were not signed by the pinned release key for the expected version.
	ErrSignature = errors.New("update: release signature rejected")
	// ErrManaged means a package manager owns the binaries; it must update them.
	ErrManaged = errors.New("update: installed by a package manager; update with it")
)

// Updater installs releases signed by Key over the running binaries in Dir.
type Updater struct {
	Key     release.PublicKey
	Source  Source
	Current string   // the running version, from the release build
	Pin     string   // if set, the exact version to run (installed even when older); never anything else
	Dir     string   // directory holding the binaries
	Names   []string // binaries to replace, without extension; the first must exist, the others only if present
	OS      string   // target of the release assets (runtime.GOOS)
	Arch    string   // runtime.GOARCH

	Now      func() time.Time // default time.Now
	LockPath string           // if set, Cycle holds this file lock, so two processes never update at once

	createTemp func(dir, pattern string) (*os.File, error) // tests; default os.CreateTemp
	inspect    func(string) (fsowner.Info, error)          // tests; default fsowner.Inspect
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

// Release is a verified release: its version and the signed checksum of each file.
type Release struct {
	Version Version
	sums    map[string]string
}

// Check fetches the signed checksums of the latest (or pinned) release and returns it when it should be
// installed. It never returns a release older than the running one unless that exact version is pinned.
func (u *Updater) Check(ctx context.Context) (*Release, error) {
	cur, err := ParseVersion(u.Current)
	if err != nil {
		return nil, ErrNotRelease
	}
	want := ""
	if u.Pin != "" {
		p, err := ParseVersion(u.Pin)
		if err != nil {
			return nil, err
		}
		want = p.String()
	}
	var sums, sig bytes.Buffer
	if err := u.Source.Fetch(ctx, want, signed, maxSums, &sums); err != nil {
		return nil, err
	}
	if err := u.Source.Fetch(ctx, want, signed+".minisig", maxSig, &sig); err != nil {
		return nil, err
	}
	comment, err := u.Key.Verify(sums.Bytes(), sig.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	// The signed comment binds the checksums to one version and a validity window, so an old signed release cannot
	// be served as a new one and a frozen feed shows up as an expired manifest.
	man, err := ParseComment(comment)
	if err != nil {
		return nil, err
	}
	if err := man.checkValidity(u.now()); err != nil {
		return nil, err
	}
	ver := man.Version
	if want != "" && ver.String() != want {
		return nil, fmt.Errorf("%w: asked for %s, release is %s", ErrSignature, want, ver)
	}
	if want == "" && !cur.Less(ver) || want != "" && ver == cur {
		return nil, ErrUpToDate
	}
	m, err := parseSums(sums.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	return &Release{Version: ver, sums: m}, nil
}

// Apply downloads the release's binaries, checks each against the signed checksum, and only then swaps them in,
// all or none. The running processes keep their old files open; the new version runs from the next start.
func (u *Updater) Apply(ctx context.Context, r *Release) error {
	// Before anything is downloaded or written: only replace programs this user owns, in a place only they control.
	names, err := u.checkOwner()
	if err != nil {
		return err
	}
	type job struct{ dst, staged string }
	var jobs []job
	cleanup := func() {
		for _, j := range jobs {
			os.Remove(j.staged)
		}
	}
	for _, name := range names {
		dst := filepath.Join(u.Dir, name+exeSuffix(u.OS))
		os.Remove(dst + ".old") // left by an earlier swap on Windows, where a running file cannot be deleted
		asset := fmt.Sprintf("%s_%s_%s_%s%s", name, r.Version, u.OS, u.Arch, exeSuffix(u.OS))
		want, ok := r.sums[asset]
		if !ok {
			cleanup()
			return fmt.Errorf("update: %s is not in the signed checksums", asset)
		}
		staged, err := u.download(ctx, r.Version, asset, want)
		if staged != "" {
			jobs = append(jobs, job{dst, staged})
		}
		if err != nil {
			cleanup()
			return err
		}
	}
	dsts := make([]string, len(jobs))
	for i, j := range jobs {
		dsts[i] = j.dst
	}
	if err := u.writeJournal(dsts); err != nil {
		cleanup()
		return err
	}
	for i, j := range jobs {
		if err := swap(j.dst, j.staged); err != nil {
			for _, d := range jobs[:i] {
				os.Rename(d.dst+".old", d.dst) // roll back what was swapped
			}
			cleanup()
			os.Remove(u.journalPath())
			return err
		}
	}
	os.Remove(u.journalPath()) // the swap is complete: nothing to repair any more
	for _, j := range jobs {
		os.Remove(j.dst + ".old")
	}
	return nil
}

// Update checks and applies in one step and returns the installed version.
func (u *Updater) Update(ctx context.Context) (Version, error) {
	r, err := u.Check(ctx)
	if err != nil {
		return Version{}, err
	}
	if err := u.Apply(ctx, r); err != nil {
		return Version{}, err
	}
	return r.Version, nil
}

// download fetches asset into a private temporary file next to its destination and verifies it. The returned
// path is set even on failure when a file was created, so the caller removes it.
func (u *Updater) download(ctx context.Context, v Version, asset, wantHex string) (string, error) {
	create := u.createTemp
	if create == nil {
		create = os.CreateTemp
	}
	f, err := create(u.Dir, ".parley-update-*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	h := sha256.New()
	err = u.Source.Fetch(ctx, v.String(), asset, maxBinary, io.MultiWriter(f, h))
	err = errors.Join(err, f.Close()) // a late write error shows up at close
	if err != nil {
		return path, err
	}
	want, _ := hex.DecodeString(wantHex) // parseSums guarantees valid hex
	if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return path, fmt.Errorf("update: %s does not match the signed checksum", asset)
	}
	return path, os.Chmod(path, 0o755)
}

// swap puts staged in place of dst. The old file is renamed aside first, because a running executable can be
// renamed but not overwritten or deleted on Windows; the same steps work everywhere.
func swap(dst, staged string) error {
	if err := os.Rename(dst, dst+".old"); err != nil {
		return err
	}
	if err := os.Rename(staged, dst); err != nil {
		os.Rename(dst+".old", dst)
		return err
	}
	return nil
}

func exeSuffix(goos string) string {
	if goos == "windows" {
		return ".exe"
	}
	return ""
}

// parseSums reads a sha256sum-format body: "<64 lowercase hex>  <base name>" lines, no duplicates.
func parseSums(b []byte) (map[string]string, error) {
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		sum, name, _ := strings.Cut(sc.Text(), "  ")
		if len(sum) != 64 || name == "" || strings.ContainsAny(name, `\/`) {
			return nil, errors.New("malformed checksum line")
		}
		if _, err := hex.DecodeString(sum); err != nil || sum != strings.ToLower(sum) {
			return nil, errors.New("malformed checksum")
		}
		if _, dup := m[name]; dup {
			return nil, errors.New("duplicate checksum entry")
		}
		m[name] = sum
	}
	if len(m) == 0 {
		return nil, errors.New("no checksums")
	}
	return m, nil
}
