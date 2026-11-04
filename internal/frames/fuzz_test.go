// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package frames

import (
	"bytes"
	"testing"
	"time"
)

// FuzzParseEvent feeds arbitrary tunnel event bodies to the event parser. It
// must never panic, an event is exactly one of a relay frame or a sealed
// message, and an accepted relay frame has ids the gateway would accept.
func FuzzParseEvent(f *testing.F) {
	f.Add(`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"AQID","expires_at":1800000900000}`)
	f.Add(`{"t":"prekey_reply","id":"r1","from":"dev-b","prekey":"CQg="}`)
	f.Add(`{"t":"prekey_refused","id":"r1","from":"dev-b","reason":"offline","retry_after_ms":10}`)
	f.Add(a2a(`[{"raw":"c2VhbGVk","mediaType":"application/vnd.parley.sealed"}]`))
	f.Add(``)
	f.Add(`{"t":"x"}`)
	f.Add(`{"t":"prekey_request","id":"r1","id":"r2","from":"dev-a","nonce":"AQID","expires_at":1}`)
	f.Add(`{"T":"prekey_refused","id":"r1","from":"dev-b","reason":"rate_limited","retry_after_ms":9223372036854775807}`)
	f.Add(`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"AQ\nID","expires_at":1}`)
	f.Add(`{"a2a":"1.0","x":[[[[{"k":1}]]]]}`)
	f.Fuzz(func(t *testing.T, body string) {
		ev, err := ParseEvent(body)
		if err != nil {
			if ev.Relay != nil || ev.Sealed != nil {
				t.Fatal("an error came with an event")
			}
			return
		}
		if (ev.Relay == nil) == (ev.Sealed == nil) {
			t.Fatal("an event is exactly one of a relay frame and a sealed message")
		}
		if r := ev.Relay; r != nil && (!ValidID(r.ID) || !ValidID(r.Peer) || r.RetryAfter < 0 || r.RetryAfter > 24*time.Hour) {
			t.Fatal("accepted a relay frame with an id the gateway would refuse, or a wrapped retry time")
		}
		if len(ev.Sealed) > MaxEventBytes {
			t.Fatal("sealed message over the cap")
		}
	})
}

// FuzzDecodePrekey and FuzzUnpackInner: a blob that decodes re-encodes to
// the same bytes (one spelling per prekey), and nothing panics.
func FuzzDecodePrekey(f *testing.F) {
	f.Add(EncodePrekey(signedPrekey(f)))
	f.Add([]byte{})
	f.Add(make([]byte, 200))
	f.Add(append(EncodePrekey(signedPrekey(f)), 0))
	f.Add(EncodePrekey(signedPrekey(f))[:100])
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := DecodePrekey(b)
		if err == nil && !bytes.Equal(EncodePrekey(s), b) {
			t.Fatal("decoded blob re-encodes differently")
		}
	})
}

func FuzzUnpackInner(f *testing.F) {
	f.Add(PackInner(signedPrekey(f), []byte("content")))
	f.Add(PackInner(nil, []byte("content")))
	f.Add([]byte{1, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		next, content, err := UnpackInner(b)
		if err != nil {
			return
		}
		if !bytes.Equal(PackInner(next, content), b) {
			t.Fatal("unpacked payload packs differently")
		}
	})
}
