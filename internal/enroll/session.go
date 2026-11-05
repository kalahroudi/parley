// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"errors"
	"regexp"
)

// SessionService is the keychain service the signed-in session is filed under.
const SessionService = "parley-session"

// ErrNoSession means the user has not signed in (or the session was used up).
var ErrNoSession = errors.New("enroll: not signed in (run parley-cli login)")

// SessionStore holds the gateway session `login` obtains until `enroll` has used
// it. It is the OS keychain in production and is never a plain file.
type SessionStore interface {
	Save(tenant, token string) error
	Load(tenant string) (string, error)
	Clear(tenant string) error
}

// Keyring is the OS keychain as KeyringSessions uses it. Get returns
// ErrKeyringNotFound for a missing entry.
type Keyring interface {
	Get(service, user string) (string, error)
	Set(service, user, secret string) error
	Delete(service, user string) error
}

// ErrKeyringNotFound is what a Keyring returns for a missing entry.
var ErrKeyringNotFound = errors.New("enroll: keychain entry not found")

// KeyringSessions is a SessionStore in a Keyring, one entry per tenant.
type KeyringSessions struct{ KR Keyring }

var sessionToken = regexp.MustCompile(`^ps_[A-Za-z0-9_-]{1,64}\.[0-9a-f]{64}$`)

func validToken(tenant, token string) bool {
	return sessionToken.MatchString(token) && len(token) > len("ps_"+tenant+".") && token[:len("ps_"+tenant+".")] == "ps_"+tenant+"."
}

func (k KeyringSessions) Save(tenant, token string) error {
	if !validToken(tenant, token) {
		return errors.New("enroll: not a session token for this tenant")
	}
	if err := k.KR.Set(SessionService, tenant, token); err != nil {
		// The keychain's text is not passed on: it can carry service details.
		return errors.New("enroll: could not store the session in the OS keychain")
	}
	return nil
}

func (k KeyringSessions) Load(tenant string) (string, error) {
	t, err := k.KR.Get(SessionService, tenant)
	if errors.Is(err, ErrKeyringNotFound) {
		return "", ErrNoSession
	}
	if err != nil {
		return "", errors.New("enroll: OS keychain unavailable")
	}
	if !validToken(tenant, t) {
		return "", errors.New("enroll: the stored session is not valid (run parley-cli login again)")
	}
	return t, nil
}

func (k KeyringSessions) Clear(tenant string) error {
	if err := k.KR.Delete(SessionService, tenant); err != nil && !errors.Is(err, ErrKeyringNotFound) {
		return errors.New("enroll: could not remove the session from the OS keychain")
	}
	return nil
}
