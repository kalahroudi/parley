// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"
)

// testdata/vectors.json is published: other implementations check their
// encoding and signatures against it. Changing it is a wire-format change.
func TestPublishedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		RootSeed      string `json:"root_seed"`
		RootPublicKey string `json:"root_public_key"`
		Vectors       []struct {
			Name       string `json:"name"`
			Tenant     string `json:"tenant"`
			Owner      string `json:"owner"`
			DeviceID   string `json:"device_id"`
			SigningKey string `json:"signing_key"`
			Version    string `json:"version"`
			NotAfter   string `json:"not_after"`
			Encoded    string `json:"encoded"`
			Signature  string `json:"signature"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	seed := unhex(t, f.RootSeed)
	root := ed25519.NewKeyFromSeed(seed)
	rootPub := root.Public().(ed25519.PublicKey)
	if !bytes.Equal(rootPub, unhex(t, f.RootPublicKey)) {
		t.Fatal("root public key mismatch")
	}
	if len(f.Vectors) < 3 {
		t.Fatal("vectors missing")
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			ver, err := strconv.ParseUint(v.Version, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			na, err := strconv.ParseInt(v.NotAfter, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			b := Binding{Tenant: v.Tenant, Owner: v.Owner, DeviceID: v.DeviceID,
				SigningKey: unhex(t, v.SigningKey), Version: ver, NotAfter: time.Unix(na, 0)}
			if got := hex.EncodeToString(b.Encode()); got != v.Encoded {
				t.Fatalf("encoding changed:\n got %s\nwant %s", got, v.Encoded)
			}
			s, err := Sign(root, b)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(s.Signature); got != v.Signature {
				t.Fatalf("signature changed:\n got %s\nwant %s", got, v.Signature)
			}
			// The published signature, not just our own, must verify.
			s.Signature = unhex(t, v.Signature)
			if err := Verify(rootPub, s, time.Unix(na, 0).Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
