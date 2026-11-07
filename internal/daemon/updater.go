// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/release"
	"github.com/kalahroudi/parley/internal/update"
	releasekey "github.com/kalahroudi/parley/release"
)

// maxFirstUpdateDelay spreads the first check after a start, so a fleet restarted together does not call the
// release source at the same moment.
const maxFirstUpdateDelay = 5 * time.Minute

// NewUpdater builds the updater for the running release: the pinned project key, the policy's source and pin, and
// the directory of exe (links resolved). It fails with update.ErrNotRelease for builds that are not releases and
// update.ErrManaged for binaries a package manager owns. stateDir holds the lock that keeps the daemon and
// parley-cli from updating at the same time. Both parleyd and parley-cli use it.
func NewUpdater(pol UpdatePolicy, version, exe, stateDir string) (*update.Updater, error) {
	return newUpdater(releasekey.Public(), pol, version, exe, stateDir)
}

func newUpdater(keyFile []byte, pol UpdatePolicy, version, exe, stateDir string) (*update.Updater, error) {
	if _, err := update.ParseVersion(version); err != nil {
		return nil, update.ErrNotRelease
	}
	key, err := release.ParsePublicKey(keyFile)
	if err != nil {
		return nil, err
	}
	dir, err := update.Locate(exe)
	if err != nil {
		return nil, err
	}
	base := update.DefaultSource
	if pol.Source != "" {
		base = pol.Source
	}
	return &update.Updater{Key: key, Source: update.HTTPSource{Base: base}, Current: version, Pin: pol.Pin, Dir: dir,
		Names: []string{"parleyd", "parley-cli"}, OS: runtime.GOOS, Arch: runtime.GOARCH,
		LockPath: filepath.Join(stateDir, "update.lock")}, nil
}

// runUpdate checks for a release on the policy's schedule: in auto mode it installs a verified newer one, in check
// mode it only records that one exists. The new version is written to disk and runs from the next start of
// parleyd (the daemon does not own the service manager), which the log says. A daemon that is not a release
// build, or whose files a package manager owns, does not update itself. Only versions and reason codes are logged.
func (d *Daemon) runUpdate(ctx context.Context) error {
	u := d.deps.Updater
	if u == nil {
		exe, err := d.deps.Executable()
		if err == nil {
			u, err = NewUpdater(d.policy, d.deps.Version, exe, d.dirs.State)
		}
		if err != nil {
			d.deps.Log.Info("self-update is off for this installation", logx.ID("component", "update"))
			return nil
		}
	}
	first := time.Duration(rand.Int64N(int64(maxFirstUpdateDelay)))
	every := d.policy.Interval
	if d.deps.UpdateEvery > 0 {
		first, every = d.deps.UpdateEvery, d.deps.UpdateEvery
	}
	u.Run(ctx, first, every, d.policy.Mode == UpdateAuto, d.reportUpdate)
	return nil
}

func (d *Daemon) reportUpdate(st update.Status) {
	if err := update.WriteStatus(d.dirs.State, st); err != nil {
		d.deps.Log.Warn("update status not recorded", logx.ID("component", "update"))
	}
	comp := logx.ID("component", "update")
	switch st.State {
	case update.StateInstalled:
		d.deps.Log.Info("update installed; restart parleyd to run it", comp, logx.ID("version", versionID(st.Available)))
	case update.StateAvailable:
		d.deps.Log.Info("update available", comp, logx.ID("version", versionID(st.Available)))
	case update.StateError:
		d.deps.Log.Warn("update check failed", comp, logx.ID("reason", st.Code))
	}
}

// versionID spells a version the way log identifiers allow: v1.2.3 becomes v1-2-3.
func versionID(v string) string { return strings.ReplaceAll(v, ".", "-") }

// Executable is the default for Deps.Executable.
func Executable() (string, error) { return os.Executable() }
