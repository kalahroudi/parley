// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package binding

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

// FuzzDecodeVerify feeds arbitrary bytes to the JSON decoder a gateway reply
// goes through, then to Verify and a Tracker. Nothing may panic, and the only
// statement the pinned root signed is the genuine binding: anything else that
// verifies would be a forged or malleable binding. The root key is fixed so the
// committed corpus (testdata/fuzz/FuzzDecodeVerify) keeps its valid signatures.
func FuzzDecodeVerify(f *testing.F) {
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	pub := root.Public().(ed25519.PublicKey)
	at := time.Unix(1_800_000_000, 0).UTC()
	genuine, err := Sign(root, Binding{Tenant: "t1", Owner: "a@example.com", DeviceID: "d1",
		SigningKey: bytes.Repeat([]byte{7}, ed25519.PublicKeySize), Version: 5, NotAfter: at.Add(Lifetime)})
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := json.Marshal(genuine)
	f.Add(raw)
	f.Add(raw[:len(raw)/2])
	f.Add(bytes.Replace(raw, []byte(`"version":5`), []byte(`"version":6`), 1))
	f.Add(bytes.Replace(raw, []byte(`"version":5`), []byte(`"version":0`), 1))
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"tenant":1}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		var s Signed
		if json.Unmarshal(in, &s) != nil {
			return
		}
		tr, err := NewTracker(pub, nil)
		if err != nil {
			t.Fatal(err)
		}
		verr := Verify(pub, &s, at)
		aerr := tr.Accept(&s, at)
		if (verr == nil || aerr == nil) && !bytes.Equal(s.Encode(), genuine.Encode()) {
			t.Fatalf("a binding the root never signed was accepted: %+v", s)
		}
		if aerr == nil && verr != nil {
			t.Fatal("the tracker accepted what Verify refuses")
		}
	})
}
