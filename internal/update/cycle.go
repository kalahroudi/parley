// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kalahroudi/parley/internal/fsowner"
	"github.com/kalahroudi/parley/internal/fsperm"
)

const journalName = ".parley-update.journal"

// journalPath is where Apply records, before its first rename, which programs it is about to swap.
func (u *Updater) journalPath() string { return filepath.Join(u.Dir, journalName) }

// writeJournal records the programs about to be swapped. Its presence at the next start means a swap may have
// been interrupted (Recover puts the old programs back).
func (u *Updater) writeJournal(dsts []string) error {
	var b bytes.Buffer
	for _, d := range dsts {
		b.WriteString(filepath.Base(d) + "\n")
	}
	f, err := os.OpenFile(u.journalPath(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b.Bytes())
	serr := f.Sync()
	return errors.Join(werr, serr, f.Close())
}

// Recover makes the install directory consistent after a crash or kill during an update, and removes what an
// update leaves behind. It is safe to run at any time, by anyone who passes the owner check, and does nothing when
// there is nothing to repair:
//
//   - A journal means a swap may have been interrupted. Every program with a ".old" file beside it is put back, so
//     the programs are all the old version again (a program missing between the two renames comes back too) and
//     the next cycle simply tries again.
//   - Staged downloads (".parley-update-*") and finished ".old" files (left on Windows while the old program was
//     still running) are deleted when no swap is in doubt.
func (u *Updater) Recover() error {
	inspect := u.inspect
	if inspect == nil {
		inspect = fsowner.Inspect
	}
	// The programs themselves may be missing mid-swap, so only the directory is checked here.
	if err := checkInstall(u.Dir, nil, inspect); err != nil {
		return err
	}
	known := map[string]bool{}
	for _, n := range u.Names {
		known[n+exeSuffix(u.OS)] = true
	}
	var removeErr error
	data, err := os.ReadFile(u.journalPath())
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if !known[line] { // only our own programs, whatever the file says
				continue
			}
			dst := filepath.Join(u.Dir, line)
			if _, err := os.Lstat(dst + ".old"); err == nil {
				if err := os.Rename(dst+".old", dst); err != nil {
					return err
				}
			}
		}
		removeErr = os.Remove(u.journalPath()) // reported after the rest of the cleanup
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	stale, _ := filepath.Glob(filepath.Join(u.Dir, ".parley-update-*"))
	for n := range known {
		stale = append(stale, filepath.Join(u.Dir, n+".old"))
	}
	for _, p := range stale {
		os.Remove(p) // best effort: a running program's ".old" cannot be removed on Windows yet
	}
	return removeErr
}

// Cycle runs one update round: recover from an interrupted one, check the signed release feed, and, when install
// is true and a newer verified release exists, install it. Installing is only reachable through a *Release that
// Check returned, i.e. after the signature, expiry, version and checksum checks. The result never carries error
// text.
func (u *Updater) Cycle(ctx context.Context, install bool) Status {
	st := Status{State: StateError, CheckedAt: u.now().Unix(), Current: u.Current}
	if u.LockPath != "" { // the daemon and parley-cli must not swap programs at the same time
		release, err := fsperm.Lock(u.LockPath)
		if err != nil {
			st.Code = ErrorCode(err)
			return st
		}
		defer release()
	}
	if err := u.Recover(); err != nil {
		st.Code = ErrorCode(err)
		return st
	}
	r, err := u.Check(ctx)
	if errors.Is(err, ErrUpToDate) {
		st.State = StateUpToDate
		return st
	}
	if err != nil {
		st.Code = ErrorCode(err)
		return st
	}
	st.Available = r.Version.String()
	if !install {
		st.State = StateAvailable
		return st
	}
	if err := u.Apply(ctx, r); err != nil {
		st.Available, st.Code = "", ErrorCode(err)
		return st
	}
	st.State = StateInstalled
	return st
}

// Run runs Cycle after first and then every interval until ctx ends, handing each result to report.
func (u *Updater) Run(ctx context.Context, first, every time.Duration, install bool, report func(Status)) {
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		report(u.Cycle(ctx, install))
		t.Reset(every)
	}
}
