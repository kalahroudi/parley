// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package frames

import (
	"errors"
	"strings"
	"testing"
)

// Spellings that a decoder may read as the same field, or as a legal value, but that are not the one canonical form:
// escaped and folded keys, and invalid UTF-8, NUL, control and bidi characters in every string a frame carries.
func TestParseEventRefusesHostileSpellings(t *testing.T) {
	nonce, blob := b64([]byte("n0n")), b64([]byte("blob"))
	req := func(id, from string) string {
		return `{"t":"prekey_request","id":"` + id + `","from":"` + from + `","nonce":"` + nonce + `","expires_at":1}`
	}
	refused := func(id, from string) string {
		return `{"t":"prekey_refused","id":"` + id + `","from":"` + from + `","reason":"refused"}`
	}
	bad := map[string]string{
		"escaped duplicate key":      `{"t":"prekey_request","id":"r1","id":"r2","from":"dev-a","nonce":"` + nonce + `","expires_at":1}`,
		"escaped miscased key":       `{"t":"prekey_request","Id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":1}`,
		"Kelvin sign for k":          `{"a2a":"1.0","tasK":{}}`,
		"long s for s":               `{"a2a":"1.0","task":{"ſtatus":{}}}`,
		"Kelvin in a read key":       `{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":1,"K":1}`,
		"NUL in the id":              req("r\\u00001", "dev-a"),
		"raw NUL in the id":          req("r\x001", "dev-a"),
		"newline in the id":          req("r1\\n", "dev-a"),
		"raw newline in the id":      req("r1\n", "dev-a"),
		"bidi in the id":             req("r1‮", "dev-a"),
		"zero width in the from":     req("r1", "dev​-a"),
		"invalid UTF-8 in the from":  req("r1", "dev\xff"),
		"control in the from":        req("r1", "dev\x1b[0m"),
		"non-ASCII digit in the id":  req("r١", "dev-a"),
		"fullwidth in the id":        req("r１", "dev-a"),
		"invalid UTF-8 in the id":    refused("\xc0\xaf", "dev-a"),
		"reason with a bidi":         `{"t":"prekey_refused","id":"r1","from":"dev-a","reason":"refused‮"}`,
		"reason with invalid UTF-8":  `{"t":"prekey_refused","id":"r1","from":"dev-a","reason":"refused\xff"}`,
		"reason with a NUL":          `{"t":"prekey_refused","id":"r1","from":"dev-a","reason":"refused\u0000"}`,
		"reason in another case":     `{"t":"prekey_refused","id":"r1","from":"dev-a","reason":"Refused"}`,
		"kind with a trailing space": `{"t":"prekey_reply ","id":"r1","from":"dev-a","prekey":"` + blob + `"}`,
		"kind with invalid UTF-8":    "{\"t\":\"prekey_reply\xff\",\"id\":\"r1\",\"from\":\"dev-a\",\"prekey\":\"" + blob + "\"}",
		"nonce with a NUL":           `{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `\u0000","expires_at":1}`,
		"nonce with a bidi":          `{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"‮` + nonce + `","expires_at":1}`,
		"media type with a NUL":      `{"a2a":"1.0","task":{"status":{"message":{"parts":[{"raw":"c2VhbGVk","mediaType":"application/vnd.parley.sealed\u0000"}]}}}}`,
		"media type in upper case":   `{"a2a":"1.0","task":{"status":{"message":{"parts":[{"raw":"c2VhbGVk","mediaType":"Application/vnd.parley.sealed"}]}}}}`,
		"raw with a NUL":             `{"a2a":"1.0","task":{"status":{"message":{"parts":[{"raw":"c2VhbGVk\u0000","mediaType":"application/vnd.parley.sealed"}]}}}}`,
		"raw with invalid UTF-8":     "{\"a2a\":\"1.0\",\"task\":{\"status\":{\"message\":{\"parts\":[{\"raw\":\"c2Vh\xffbGVk\",\"mediaType\":\"application/vnd.parley.sealed\"}]}}}}",
		"raw with a bidi":            `{"a2a":"1.0","task":{"status":{"message":{"parts":[{"raw":"c2VhbGVk‮","mediaType":"application/vnd.parley.sealed"}]}}}}`,
		"version with a NUL":         `{"a2a":"1.0\u0000"}`,
	}
	for name, body := range bad {
		ev, err := ParseEvent(body)
		if err != nil && !errors.Is(err, ErrFormat) && !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: an error that is neither format nor unsupported: %v", name, err)
		}
		if err == nil {
			t.Errorf("%s: accepted: %+v", name, ev)
		}
	}
	// a frame is read from a gateway that can send anything: nothing it sends may make a bounded parse unbounded
	if _, err := ParseEvent(strings.Repeat(`{"a":`, 5000)); !errors.Is(err, ErrFormat) {
		t.Errorf("deep objects: %v", err)
	}
	if _, err := ParseEvent(`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":9223372036854775807}`); err != nil {
		t.Errorf("a huge expiry must parse without overflow: %v", err)
	}
	for _, v := range []string{"-1", "0", "1e400", "9223372036854775808", "-9223372036854775809", "1.5", `"1"`, "null"} {
		if _, err := ParseEvent(`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":` + v + `}`); err == nil {
			t.Errorf("expires_at %s accepted", v)
		}
		if _, err := ParseEvent(`{"t":"prekey_refused","id":"r1","from":"dev-a","reason":"refused","retry_after_ms":` + v + `}`); err == nil && v != "0" && v != "null" {
			t.Errorf("retry_after_ms %s accepted", v)
		}
	}
}
