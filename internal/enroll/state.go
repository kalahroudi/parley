// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/fsperm"
)

// The phases of an enrollment, saved after each step so a restart resumes where
// it stopped. A run that finds no state file is "not enrolled".
//
//	pinned      the root key is pinned (its fingerprint was checked or confirmed)
//	keyed       the device key exists in the key store; its public half is recorded
//	requesting  the request id and poll secret are chosen and saved; the request may or may not have reached the gateway
//	requested   the gateway accepted the request (the sign-in credential is no longer needed)
//	approved    the admin approved and the root-signed binding is verified and recorded
//	bound       config.json is written; the device can start parleyd
const (
	PhasePinned     = "pinned"
	PhaseKeyed      = "keyed"
	PhaseRequesting = "requesting"
	PhaseRequested  = "requested"
	PhaseApproved   = "approved"
	PhaseBound      = "bound"
)

const (
	stateFormat   = 1
	stateFile     = "enrollment.json"
	maxStateBytes = 16 << 10
	maxReplaces   = 32
)

// ErrBadState means the saved enrollment state is damaged or inconsistent. The
// run stops: guessing would risk a second key or a second identity.
var ErrBadState = errors.New("enroll: saved enrollment state (enrollment.json in the state directory) is damaged or inconsistent, and was not changed; restore it from a backup, or move it away and run enroll again to start over with a new device key (and ask your admin to revoke any earlier request of this device)")

var (
	idRe   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	pollRe = regexp.MustCompile(`^[0-9a-f]{48,64}$`)
)

// state is the enrollment in progress. It holds the poll secret (which reads only
// this request's status; the binding it returns is public and root-signed). The
// device key is in the key store, never here, only its public half.
type state struct {
	Format        int      `json:"format"`
	Phase         string   `json:"phase"`
	Gateway       string   `json:"gateway_url"`
	Tenant        string   `json:"tenant"`
	RootPublicKey []byte   `json:"root_public_key"`
	Name          string   `json:"name"`
	KeyStore      string   `json:"key_store"`
	KeyAccount    string   `json:"key_account"`
	PublicKey     []byte   `json:"public_key,omitempty"`
	ID            string   `json:"id,omitempty"`
	Poll          string   `json:"poll,omitempty"`
	Replaces      []string `json:"replaces,omitempty"` // device ids this enrollment replaced, for the admin to revoke
}

func (s *state) save(dir string) error {
	data, err := marshal(s)
	if err != nil {
		return err
	}
	return fsperm.WriteAtomic(filepath.Join(dir, stateFile), data)
}

// loadState returns os.ErrNotExist (wrapped) when there is no state.
func loadState(dir string) (*state, error) {
	path := filepath.Join(dir, stateFile)
	if err := fsperm.CheckFile(path); err != nil {
		return nil, err // a missing file satisfies errors.Is(err, os.ErrNotExist)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil || len(data) > maxStateBytes {
		return nil, ErrBadState
	}
	var s state
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, ErrBadState
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrBadState
	}
	if !s.valid() {
		return nil, ErrBadState
	}
	return &s, nil
}

// valid checks every field the phase implies, so a state that was edited or half
// written cannot steer a run.
func (s *state) valid() bool {
	if s.Format != stateFormat || daemon.ValidGatewayURL(s.Gateway) != nil || !daemon.ValidID(s.Tenant) || !daemon.ValidID(s.KeyAccount) ||
		len(s.RootPublicKey) != ed25519.PublicKeySize || ValidName(s.Name) != nil ||
		(s.KeyStore != daemon.KeyStoreKeychain && s.KeyStore != daemon.KeyStoreFile) || len(s.Replaces) > maxReplaces {
		return false
	}
	for _, id := range s.Replaces {
		if !daemon.ValidID(id) {
			return false
		}
	}
	keyed := len(s.PublicKey) == ed25519.PublicKeySize
	chosen := idRe.MatchString(s.ID) && pollRe.MatchString(s.Poll)
	switch s.Phase {
	case PhasePinned:
		return len(s.PublicKey) == 0 && s.ID == "" && s.Poll == ""
	case PhaseKeyed:
		return keyed && s.ID == "" && s.Poll == ""
	case PhaseRequesting, PhaseRequested, PhaseApproved, PhaseBound:
		return keyed && chosen
	}
	return false
}
