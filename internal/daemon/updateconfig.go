// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"fmt"
	"time"

	"github.com/kalahroudi/parley/internal/update"
)

// Update modes, from the most permissive to the most restrictive.
const (
	UpdateAuto  = "auto"  // check on a schedule and install a verified newer release
	UpdateCheck = "check" // check on a schedule and record what is available; install only when asked (parley-cli update)
	UpdateOff   = "off"   // never contact the release source
)

// UpdateEnv is the environment variable an operator (a service unit, a container, a package) can set to restrict
// updates without touching config.json: off or check. It can only tighten what the configuration allows.
const UpdateEnv = "PARLEY_UPDATE"

const (
	DefaultUpdateInterval = 6 * time.Hour
	minUpdateInterval     = time.Hour
	maxUpdateInterval     = 7 * 24 * time.Hour
)

// UpdateConfig is the "update" section of config.json (journey J). Whatever it says, an update is installed only
// from a release signed by the project key compiled into the binary (internal/update).
type UpdateConfig struct {
	// Mode is "auto" (default), "check" or "off".
	Mode string `json:"mode,omitempty"`
	// Pin holds the device on one exact version (vMAJOR.MINOR.PATCH): that version is installed, even if older,
	// and no other ever is. This is the channel pin; there is one channel, the project's releases.
	Pin string `json:"pin,omitempty"`
	// Interval between checks, 1h to 168h, default 6h.
	Interval string `json:"interval,omitempty"`
	// Source is a mirror with the layout of GitHub releases; https (or loopback http). Default: the project's.
	Source string `json:"source,omitempty"`

	interval time.Duration
}

func (u *UpdateConfig) validate() error {
	switch u.Mode {
	case "":
		u.Mode = UpdateAuto
	case UpdateAuto, UpdateCheck, UpdateOff:
	default:
		return fmt.Errorf("update.mode must be auto, check or off")
	}
	if u.Pin != "" {
		v, err := update.ParseVersion(u.Pin)
		if err != nil || v.String() != u.Pin {
			return fmt.Errorf("update.pin must be a version like v1.2.3")
		}
	}
	u.interval = DefaultUpdateInterval
	if u.Interval != "" {
		d, err := time.ParseDuration(u.Interval)
		if err != nil || d < minUpdateInterval || d > maxUpdateInterval {
			return fmt.Errorf("update.interval must be a duration between 1h and 168h")
		}
		u.interval = d
	}
	if u.Source != "" {
		if err := update.ValidSource(u.Source); err != nil {
			return fmt.Errorf("update.source: %v", err)
		}
	}
	return nil
}

// UpdatePolicy is what the daemon and parley-cli actually follow: the configuration with the operator's
// environment applied.
type UpdatePolicy struct {
	Mode     string
	Pin      string
	Interval time.Duration
	Source   string // empty: the project's releases
}

// Policy resolves the update settings. A missing section means defaults (auto). The environment variable
// PARLEY_UPDATE can only restrict (auto -> check -> off). A value it cannot understand fails closed: the policy is
// "off" and the error says why, so a typo in a unit file never leaves updates running.
func (c Config) Policy(getenv func(string) string) (UpdatePolicy, error) {
	p := UpdatePolicy{Mode: UpdateAuto, Interval: DefaultUpdateInterval}
	if u := c.Update; u != nil {
		// A section that did not go through validation (a hand-built Config) is not trusted: anything unexpected
		// means no updates.
		if cp := *u; cp.validate() != nil {
			p = UpdatePolicy{Mode: UpdateOff, Interval: DefaultUpdateInterval}
			return p, fmt.Errorf("update configuration is invalid")
		}
		p = UpdatePolicy{Mode: u.Mode, Pin: u.Pin, Interval: u.interval, Source: u.Source}
		if u.Mode == "" {
			p.Mode = UpdateAuto
		}
		if p.Interval == 0 {
			p.Interval = DefaultUpdateInterval
		}
	}
	switch env := getenv(UpdateEnv); env {
	case "", UpdateAuto:
	case UpdateCheck:
		if p.Mode == UpdateAuto {
			p.Mode = UpdateCheck
		}
	case UpdateOff:
		p.Mode = UpdateOff
	default:
		p.Mode = UpdateOff
		return p, fmt.Errorf("%s must be auto, check or off", UpdateEnv)
	}
	return p, nil
}
