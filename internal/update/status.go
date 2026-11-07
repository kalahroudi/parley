// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kalahroudi/parley/internal/fsperm"
)

// Status states.
const (
	StateUpToDate  = "up_to_date"
	StateAvailable = "available" // a newer verified release exists and was not installed (check mode, or asked only to check)
	StateInstalled = "installed" // installed; it runs from the next start of the program
	StateError     = "error"
)

// StatusFile is the name of the status record inside the daemon's state directory.
const StatusFile = "update-status.json"

const maxStatusBytes = 4 << 10

// Status is the outcome of the last update cycle. It holds versions, a state and a short code, never error text,
// so it is safe to print and to read from a file.
type Status struct {
	State     string `json:"state"`
	CheckedAt int64  `json:"checked_at"` // unix seconds
	Current   string `json:"current"`
	Available string `json:"available,omitempty"` // the version found (available) or put in place (installed)
	Code      string `json:"code,omitempty"`      // why a cycle failed, one of errorCodes
}

var errorCodes = map[string]error{
	"signature":   ErrSignature,
	"expired":     ErrExpired,
	"not_yet":     ErrNotYetValid,
	"not_owner":   ErrNotOwner,
	"not_release": ErrNotRelease,
	"managed":     ErrManaged,
	"pin":         ErrVersion,
	"busy":        fsperm.ErrLocked,
}

// errorCodeOrder fixes which code wins when an error matches several.
var errorCodeOrder = []string{"expired", "not_yet", "signature", "not_owner", "not_release", "managed", "pin", "busy"}

// ErrorCode names a failure for the status record: a known reason, or "failed" (network, disk, ...).
func ErrorCode(err error) string {
	for _, c := range errorCodeOrder {
		if errors.Is(err, errorCodes[c]) {
			return c
		}
	}
	return "failed"
}

// validate checks a status read from disk before anything prints or trusts it.
func (s Status) validate() error {
	switch s.State {
	case StateUpToDate, StateAvailable, StateInstalled, StateError:
	default:
		return errors.New("update: bad status state")
	}
	if _, err := ParseVersion(s.Current); err != nil {
		return err
	}
	if s.Available != "" {
		if _, err := ParseVersion(s.Available); err != nil {
			return err
		}
	}
	if _, known := errorCodes[s.Code]; s.Code != "" && !known && s.Code != "failed" {
		return errors.New("update: bad status code")
	}
	return nil
}

// WriteStatus replaces the status record in dir atomically and privately (mode 0600).
func WriteStatus(dir string, s Status) error {
	b, _ := json.Marshal(s) // a struct of strings and an integer always marshals
	f, err := os.CreateTemp(dir, ".update-status-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(b)
	err = errors.Join(werr, f.Close(), os.Chmod(tmp, 0o600))
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, StatusFile))
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// ReadStatus reads the record; ok is false when there is none. A record that is too large, malformed or carries
// anything unexpected is an error: it is only ever written by this package.
func ReadStatus(dir string) (s Status, ok bool, err error) {
	f, err := os.Open(filepath.Join(dir, StatusFile))
	if errors.Is(err, os.ErrNotExist) {
		return Status{}, false, nil
	}
	if err != nil {
		return Status{}, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStatusBytes+1))
	if err != nil {
		return Status{}, false, err
	}
	if len(data) > maxStatusBytes {
		return Status{}, false, errors.New("update: status record too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Status{}, false, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return Status{}, false, errors.New("update: trailing data in status record")
	}
	if err := s.validate(); err != nil {
		return Status{}, false, err
	}
	return s, true, nil
}

// CheckedTime is when the cycle ran.
func (s Status) CheckedTime() time.Time { return time.Unix(s.CheckedAt, 0) }
