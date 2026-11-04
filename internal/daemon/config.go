// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package daemon is the core of parleyd: configuration, the device signing key
// in the OS keychain, the OS-user-restricted local socket, a supervisor for the
// background components, and ordered graceful shutdown. It holds no task
// content; the pipeline that handles tasks plugs in through Deps and Handle.
//
// Extension points for the tasks that complete the daemon (no code ahead of them):
//   - Device connect tokens (T415): the tunnel dials the configured gateway
//     and, before each connection attempt, signs the gateway's challenge with
//     the device key for a short-lived token (internal/connect). Deps.TunnelConfig
//     replaces this (tests); it is called each time the tunnel (re)starts.
//   - Enrollment (T411): internal/enroll is what `parley-cli login` and `enroll`
//     run before any daemon exists. It pins the root by the fingerprint the admin
//     shared, creates the device key once, requests approval, waits, records the
//     root-signed binding and then writes config.json (key_account names the
//     keychain entry). Its persisted state makes it resumable at every step.
//     Daemon.SigningKey and Daemon.Trust give the device key and a trust.Daemon
//     already pinned to the configured root; New opens the rollback stores, so a
//     corrupt or rolled-back store stops startup.
//   - T412 (receive pipeline): Deps.OnEvent receives every tunnel event in
//     order and must not block for long; Daemon.Handle registers local socket
//     methods before Run; a new background job is one more Component in
//     Daemon.components (restarted with jittered backoff, stopped on shutdown).
//     Sending must go through Daemon.Trust, which refuses when the binding or
//     revocation state is missing, stale or rolled back.
//
// The security-critical pieces live in their own tier 1 packages: keystore
// (the device key and what each OS guarantees), fsperm (private directories and
// files, the instance lock), localsock (the OS-user-restricted socket) and
// supervisor (restart decisions). This package wires them to the configuration.
package daemon

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// ErrConfig means the configuration file is missing, unreadable or invalid.
// The daemon refuses to start on any of these; it has no defaults for identity.
var ErrConfig = errors.New("daemon: invalid configuration")

const (
	ConfigFormat = 1
	// DefaultRefresh is how often the revocation list is fetched (the plan asks for
	// at least weekly; hourly keeps the 7-day warning from ever showing).
	DefaultRefresh = time.Hour
	minRefresh     = time.Minute
	// maxRefresh keeps the 7-day staleness warning meaningful: a longer interval
	// would let the held list go stale before the next fetch is even tried.
	maxRefresh     = 24 * time.Hour
	maxConfigBytes = 64 << 10

	// KeyStoreKeychain is the default: the OS keychain. KeyStoreFile is an explicit
	// opt-in for headless hosts (pods, CI) that have no keychain.
	KeyStoreKeychain = "keychain"
	KeyStoreFile     = "file"
)

// Config is the parleyd configuration file (config.json in the config
// directory). It is public data: the pinned root key, ids and URLs. Secrets
// never appear in it.
type Config struct {
	Format        int    `json:"format"`
	Tenant        string `json:"tenant"`
	DeviceID      string `json:"device_id"`
	GatewayURL    string `json:"gateway_url"`
	RootPublicKey []byte `json:"root_public_key"` // 32 bytes, base64 in JSON
	KeyStore      string `json:"key_store,omitempty"`
	// KeyAccount names the keychain entry that holds the device key. Enrollment
	// chooses it before the device id exists; it defaults to the device id.
	KeyAccount string `json:"key_account,omitempty"`
	Refresh    string `json:"refresh_interval,omitempty"` // Go duration, default 1h
	LogLevel   string `json:"log_level,omitempty"`        // debug, info, warn, error

	refresh time.Duration
}

// LoadConfig reads and validates dir/config.json. Unknown fields, trailing
// data and oversized files are rejected so a typo cannot silently weaken a setting.
func LoadConfig(dir string) (Config, error) {
	f, err := os.Open(filepath.Join(dir, "config.json"))
	if err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil || len(data) > maxConfigBytes {
		return Config{}, fmt.Errorf("%w: unreadable or too large", ErrConfig)
	}
	return ParseConfig(data)
}

// ParseConfig decodes and validates configuration JSON.
func ParseConfig(data []byte) (Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Config{}, fmt.Errorf("%w: trailing data", ErrConfig)
	}
	if err := c.validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c *Config) validate() error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrConfig, what) }
	if c.Format != ConfigFormat {
		return bad("unsupported format")
	}
	// Ids must be loggable as-is, or every log line about them would be redacted.
	if !ValidID(c.Tenant) {
		return bad("tenant must be 1-64 characters of A-Z a-z 0-9 - _")
	}
	if !ValidID(c.DeviceID) {
		return bad("device_id must be 1-64 characters of A-Z a-z 0-9 - _")
	}
	if len(c.RootPublicKey) != ed25519.PublicKeySize {
		return bad("root_public_key must be a 32-byte Ed25519 key")
	}
	if err := ValidGatewayURL(c.GatewayURL); err != nil {
		return err
	}
	switch c.KeyStore {
	case "":
		c.KeyStore = KeyStoreKeychain
	case KeyStoreKeychain, KeyStoreFile:
	default:
		return bad("key_store must be keychain or file")
	}
	if c.KeyAccount == "" {
		c.KeyAccount = c.DeviceID
	} else if !ValidID(c.KeyAccount) {
		return bad("key_account must be 1-64 characters of A-Z a-z 0-9 - _")
	}
	c.refresh = DefaultRefresh
	if c.Refresh != "" {
		d, err := time.ParseDuration(c.Refresh)
		if err != nil || d < minRefresh || d > maxRefresh {
			return bad("refresh_interval must be a duration between 1m and 24h")
		}
		c.refresh = d
	}
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return bad("log_level must be debug, info, warn or error")
	}
	return nil
}

// RefreshEvery is the validated revocation refresh interval.
func (c Config) RefreshEvery() time.Duration {
	if c.refresh == 0 {
		return DefaultRefresh
	}
	return c.refresh
}

func ValidID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ValidGatewayURL requires https. Plain http is allowed only to a loopback
// host, for local development against `wrangler dev`.
func ValidGatewayURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: gateway_url must be an absolute URL without credentials, query or fragment", ErrConfig)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if h := u.Hostname(); h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return fmt.Errorf("%w: gateway_url must be https (http is for localhost only)", ErrConfig)
		}
	default:
		return fmt.Errorf("%w: gateway_url must be https", ErrConfig)
	}
	return nil
}
