// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package revocation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

// FuzzDecodeVerify feeds arbitrary bytes to the JSON decoder a gateway reply
// goes through, then to Verify and a Guard. Nothing may panic, and only the
// genuine list may be accepted (a forged or shortened list would un-revoke a
// device). The root key is fixed so the committed corpus keeps its signatures.
func FuzzDecodeVerify(f *testing.F) {
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	pub := root.Public().(ed25519.PublicKey)
	at := time.Unix(1_800_000_000, 0).UTC()
	genuine, err := Sign(root, List{Tenant: "t1", Version: 4, IssuedAt: at, Revoked: []string{"dev-a", "dev-b"}})
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := json.Marshal(genuine)
	f.Add(raw)
	f.Add(raw[:len(raw)/2])
	f.Add(bytes.Replace(raw, []byte(`"dev-b"`), []byte(`"dev-c"`), 1))
	f.Add(bytes.Replace(raw, []byte(`"dev-a","dev-b"`), []byte(`"dev-b"`), 1))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"revoked":null}`))
	f.Add([]byte(`{"tenant":"t1","version":1,"revoked":["x","x"]}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		var s Signed
		if json.Unmarshal(in, &s) != nil {
			return
		}
		g, err := NewGuard(pub, "t1", nil, at)
		if err != nil {
			t.Fatal(err)
		}
		verr := Verify(pub, &s, at)
		aerr := g.Accept(&s, at)
		if (verr == nil || aerr == nil) && !bytes.Equal(s.Encode(), genuine.Encode()) {
			t.Fatalf("a list the root never signed was accepted: %+v", s)
		}
		if aerr == nil && !g.IsRevoked("dev-a") {
			t.Fatal("an accepted list lost a revocation")
		}
		_ = g.CheckSend("dev-a", at)
		_ = g.Status(at)
	})
}
