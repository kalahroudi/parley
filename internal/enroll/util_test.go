// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kalahroudi/parley/internal/daemon"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func newKey() (ed25519.PublicKey, ed25519.PrivateKey, error) { return ed25519.GenerateKey(rand.Reader) }

// Replacing the encoder fails the three places that encode a file or a request body.
func TestEncodingFailuresAreReported(t *testing.T) {
	boom := errors.New("cannot encode")
	defer func(old func(any) ([]byte, error)) { marshal = old }(marshal)
	marshal = func(any) ([]byte, error) { return nil, boom }
	st := &state{}
	if err := st.save(t.TempDir()); !errors.Is(err, boom) {
		t.Errorf("state: %v", err)
	}
	// And the config, at the end of a real enrollment.
	e := newEnv(t)
	marshal = func(v any) ([]byte, error) {
		if _, ok := v.(daemon.Config); ok {
			return nil, boom
		}
		return json.Marshal(v)
	}
	if _, err := Enroll(context.Background(), e.opts); !errors.Is(err, boom) || e.phase() != PhaseApproved {
		t.Errorf("config: %v phase %s", err, e.phase())
	}
}
