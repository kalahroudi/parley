// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/update"
)

const updateUsage = "usage: parley-cli update status | check [-version vX.Y.Z] | apply [-version vX.Y.Z]"

// defaultUpdater builds the updater for this installation: the project's pinned key and this binary's directory.
//
//cover:ignore finds the running executable; the rest (daemon.NewUpdater) is tested with explicit paths
func defaultUpdater(pol daemon.UpdatePolicy, stateDir string) (*update.Updater, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return daemon.NewUpdater(pol, version, exe, stateDir)
}

// updateCmd is `parley-cli update`: status shows the policy and the last recorded cycle, check verifies the
// signed feed and reports what is available, apply installs a verified newer release (or the pinned/requested
// one). The same configuration, the same verification and the same locking as the daemon's background component
// apply: a pin in config.json holds here too, an operator's off (config or PARLEY_UPDATE) refuses check and
// apply, and nothing is installed that did not first pass the signature, expiry, version and checksum checks.
func updateCmd(ctx context.Context, args []string, out, errw io.Writer, dirs daemon.Dirs, getenv func(string) string, t tools) int {
	if len(args) == 0 {
		fmt.Fprintln(errw, updateUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("update "+sub, flag.ContinueOnError)
	fs.SetOutput(errw)
	want := fs.String("version", "", "use exactly this version (even an older one) instead of the latest")
	if (sub != "status" && sub != "check" && sub != "apply") || fs.Parse(args[1:]) != nil || fs.NArg() != 0 || (sub == "status" && *want != "") {
		fmt.Fprintln(errw, updateUsage)
		return 2
	}
	// A device that has not enrolled yet has no configuration and can still be updated.
	var cfg daemon.Config
	c, err := daemon.LoadConfig(dirs.Config)
	if err == nil {
		cfg = c
	} else if _, serr := os.Stat(filepath.Join(dirs.Config, "config.json")); serr == nil {
		// A configuration that exists but cannot be read must not silently drop an opt-out or a pin.
		fmt.Fprintln(errw, "error: config.json is invalid; fix it before updating")
		return 1
	}
	pol, perr := cfg.Policy(getenv)
	if sub == "status" {
		return updateStatus(out, errw, dirs, pol, perr)
	}
	if pol.Mode == daemon.UpdateOff {
		fmt.Fprintln(errw, "error: updates are turned off ("+offReason(perr)+"); nothing was contacted")
		return 1
	}
	if *want != "" {
		pol.Pin = *want
	}
	u, err := t.updater(pol, dirs.State)
	if err != nil {
		//logx:allow fatal CLI error for the operator's terminal; no task content exists in this process path
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	st := u.Cycle(ctx, sub == "apply")
	// Keep the record the daemon and `status` read, unless the lock showed another update is running.
	if st.Code != "busy" {
		update.WriteStatus(dirs.State, st)
	}
	return printCycle(out, errw, st)
}

func offReason(perr error) string {
	if perr != nil {
		return "PARLEY_UPDATE has a value that is not auto, check or off"
	}
	return "update.mode in config.json or PARLEY_UPDATE"
}

func printCycle(out, errw io.Writer, st update.Status) int {
	switch st.State {
	case update.StateUpToDate:
		fmt.Fprintln(out, "up to date:", st.Current)
	case update.StateAvailable:
		fmt.Fprintln(out, "update available:", st.Available, "(run `parley-cli update apply`)")
	case update.StateInstalled:
		fmt.Fprintln(out, "updated to", st.Available, "(verified against the project release key); restart parleyd to run it")
	default:
		fmt.Fprintln(errw, "error: update failed:", st.Code, "("+codeHelp[st.Code]+")")
		return 1
	}
	return 0
}

// codeHelp explains each status code in a sentence. The codes are fixed words, so nothing from the network is
// ever printed.
var codeHelp = map[string]string{
	"signature":   "the release is not signed by the project key",
	"expired":     "the release feed is stale: its signed manifest has expired",
	"not_yet":     "the release manifest is dated in the future; check this computer's clock",
	"not_owner":   "the install directory is not owned by you or others can write it",
	"not_release": "this is a source or go install build; it does not update itself",
	"managed":     "a package manager installed these programs; update with it",
	"pin":         "the requested version is not like v1.2.3",
	"busy":        "another update is running",
	"failed":      "could not reach or read the release source",
}

func updateStatus(out, errw io.Writer, dirs daemon.Dirs, pol daemon.UpdatePolicy, perr error) int {
	fmt.Fprintln(out, "version:", version)
	fmt.Fprintln(out, "mode:", pol.Mode)
	if perr != nil {
		fmt.Fprintln(out, "note: PARLEY_UPDATE has a value that is not auto, check or off, so updates are off")
	}
	if pol.Pin != "" {
		fmt.Fprintln(out, "pinned to:", pol.Pin)
	}
	if pol.Source != "" {
		fmt.Fprintln(out, "source:", pol.Source)
	}
	st, ok, err := update.ReadStatus(dirs.State)
	switch {
	case err != nil:
		fmt.Fprintln(errw, "error: the update status record is unreadable:", filepath.Join(dirs.State, update.StatusFile))
		return 1
	case !ok:
		fmt.Fprintln(out, "last check: none recorded")
	default:
		fmt.Fprintln(out, "last check:", st.CheckedTime().UTC().Format("2006-01-02 15:04:05 UTC"), "-", st.State)
		if st.Available != "" {
			fmt.Fprintln(out, "release:", st.Available)
		}
		if st.Code != "" {
			fmt.Fprintln(out, "reason:", st.Code, "("+codeHelp[st.Code]+")")
		}
	}
	return 0
}
