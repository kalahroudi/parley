// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package frames

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/prekey"
)

var t0 = time.Unix(1_800_000_000, 0).UTC()

func signedPrekey(t testing.TB) *prekey.Signed {
	t.Helper()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	p, err := prekey.New(prekey.Config{Tenant: "t1", DeviceID: "dev-b", SigningKeyID: "k-b", BindingVersion: 4, Signer: k,
		AllowUnlocked: true, SweepEvery: time.Hour, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	s, err := p.Issue(prekey.Request{Caller: "dev-a", Nonce: []byte("0123456789abcdef"), TaskExpiry: t0.Add(15 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// The exact JSON a daemon sends is pinned: gateway/test/device.test.ts asserts
// the same strings against the Worker, so the two sides cannot drift apart.
func TestRelayFramesAreExactlyAsThePeerExpects(t *testing.T) {
	got, err := RequestPrekey("req1", "dev-b", []byte{1, 2, 3}, time.UnixMilli(1_800_000_900_000))
	want := `{"t":"prekey_request","id":"req1","to":"dev-b","nonce":"AQID","expires_at":1800000900000}`
	if err != nil || got != want {
		t.Fatalf("request: %s %v", got, err)
	}
	if got, err = ReplyPrekey("req1", "dev-a", []byte{9, 8}); err != nil || got != `{"t":"prekey_reply","id":"req1","to":"dev-a","prekey":"CQg="}` {
		t.Fatalf("reply: %s %v", got, err)
	}
	if got, err = RefusePrekey("req1", "dev-a"); err != nil || got != `{"t":"prekey_refused","id":"req1","to":"dev-a"}` {
		t.Fatalf("refuse: %s %v", got, err)
	}
}

func TestRelayFrameBuildersRefuseBadInput(t *testing.T) {
	exp := time.UnixMilli(1_800_000_900_000)
	long := strings.Repeat("a", 65)
	cases := map[string]func() error{
		"request id":        func() error { _, e := RequestPrekey("", "dev-b", []byte{1}, exp); return e },
		"request to":        func() error { _, e := RequestPrekey("r", long, []byte{1}, exp); return e },
		"request no nonce":  func() error { _, e := RequestPrekey("r", "d", nil, exp); return e },
		"request big nonce": func() error { _, e := RequestPrekey("r", "d", make([]byte, MaxNonce+1), exp); return e },
		"request no expiry": func() error { _, e := RequestPrekey("r", "d", []byte{1}, time.Time{}); return e },
		"reply id":          func() error { _, e := ReplyPrekey("a b", "d", []byte{1}); return e },
		"reply to":          func() error { _, e := ReplyPrekey("r", "", []byte{1}); return e },
		"reply empty":       func() error { _, e := ReplyPrekey("r", "d", nil); return e },
		"reply big":         func() error { _, e := ReplyPrekey("r", "d", make([]byte, MaxPrekeyBlob+1)); return e },
		"refuse id":         func() error { _, e := RefusePrekey("", "d"); return e },
		"refuse to":         func() error { _, e := RefusePrekey("r", "d/x"); return e },
	}
	for name, f := range cases {
		if err := f(); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v, want ErrFormat", name, err)
		}
	}
}

func TestParseRelayEvents(t *testing.T) {
	nonce := b64([]byte("n0n"))
	ev, err := ParseEvent(`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":1800000900000}`)
	if err != nil || ev.Relay == nil || ev.Sealed != nil {
		t.Fatalf("%+v %v", ev, err)
	}
	r := ev.Relay
	if r.Kind != KindPrekeyRequest || r.ID != "r1" || r.Peer != "dev-a" || string(r.Nonce) != "n0n" || r.TaskExpiry.UnixMilli() != 1_800_000_900_000 {
		t.Fatalf("%+v", r)
	}
	blob := b64([]byte("blob"))
	if ev, err = ParseEvent(`{"t":"prekey_reply","id":"r1","from":"dev-b","prekey":"` + blob + `"}`); err != nil || string(ev.Relay.Prekey) != "blob" || ev.Relay.Kind != KindPrekeyReply {
		t.Fatalf("%+v %v", ev, err)
	}
	for _, reason := range []string{ReasonRefused, ReasonOffline, ReasonRateLimited} {
		ev, err = ParseEvent(`{"t":"prekey_refused","id":"r1","from":"dev-b","reason":"` + reason + `","retry_after_ms":1500}`)
		if err != nil || ev.Relay.Reason != reason || ev.Relay.RetryAfter != 1500*time.Millisecond {
			t.Fatalf("%s: %+v %v", reason, ev, err)
		}
	}
}

func TestParseRelayEventsRefuseEverythingElse(t *testing.T) {
	nonce, blob := b64([]byte("n0n")), b64([]byte("blob"))
	bad := []string{
		`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":1} trailing`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":1}{}`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":1,"extra":1}`,
		`{"t":"prekey_request","id":"","from":"dev-a","nonce":"` + nonce + `","expires_at":1}`,
		`{"t":"prekey_request","id":"r1","from":"","nonce":"` + nonce + `","expires_at":1}`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","to":"dev-b","nonce":"` + nonce + `","expires_at":1}`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `"}`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":1,"prekey":"` + blob + `"}`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":1,"reason":"refused"}`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":1,"retry_after_ms":5}`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","expires_at":1}`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"!!","expires_at":1}`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + b64(make([]byte, MaxNonce+1)) + `","expires_at":1}`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + b64(make([]byte, 100)) + `","expires_at":1}`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"AQI","expires_at":1}`, // unpadded: not the canonical text
		`{"t":"prekey_reply","id":"r1","from":"dev-b","prekey":"` + blob + `","nonce":"` + nonce + `"}`,
		`{"t":"prekey_reply","id":"r1","from":"dev-b","prekey":"` + blob + `","reason":"refused"}`,
		`{"t":"prekey_reply","id":"r1","from":"dev-b","prekey":"` + blob + `","retry_after_ms":1}`,
		`{"t":"prekey_reply","id":"r1","from":"dev-b","prekey":"` + blob + `","expires_at":1}`,
		`{"t":"prekey_reply","id":"r1","from":"dev-b"}`,
		`{"t":"prekey_reply","id":"r1","from":"dev-b","prekey":"` + b64(make([]byte, MaxPrekeyBlob+1)) + `"}`,
		`{"t":"prekey_refused","id":"r1","from":"dev-b"}`,
		`{"t":"prekey_refused","id":"r1","from":"dev-b","reason":"because"}`,
		`{"t":"prekey_refused","id":"r1","from":"dev-b","reason":"refused","nonce":"` + nonce + `"}`,
		`{"t":"prekey_refused","id":"r1","from":"dev-b","reason":"refused","prekey":"` + blob + `"}`,
		`{"t":"prekey_refused","id":"r1","from":"dev-b","reason":"refused","expires_at":1}`,
		`{"t":"prekey_refused","id":"r1","from":"dev-b","reason":"refused","retry_after_ms":-1}`,
		`{"t":"somethingelse","id":"r1","from":"dev-b"}`,
	}
	for _, b := range bad {
		if _, err := ParseEvent(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err=%v, want ErrFormat", b, err)
		}
	}
}

func TestParseEventUnsupportedAndOversize(t *testing.T) {
	for _, b := range []string{`{}`, `{"a2a":"2.0"}`, `{"x":1}`} {
		if _, err := ParseEvent(b); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v, want ErrUnsupported", b, err)
		}
	}
	for _, b := range []string{``, `nope`, `[]`, `"x"`, `{"t":1}`, strings.Repeat(" ", MaxEventBytes+1)} {
		if _, err := ParseEvent(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%q: %v, want ErrFormat", b[:min(len(b), 20)], err)
		}
	}
}

func a2a(parts string) string {
	return `{"a2a":"1.0","task":{"id":"x","status":{"state":"TASK_STATE_WORKING","message":{"messageId":"m","parts":` + parts + `,"metadata":{"parley":{"kind":"STATUS","from":"liar"}}}}}}`
}

func TestParseSealedA2AEvent(t *testing.T) {
	wire := []byte("sealed envelope bytes!")
	ev, err := ParseEvent(a2a(`[{"raw":"` + b64(wire) + `","mediaType":"application/vnd.parley.sealed"}]`))
	if err != nil || ev.Relay != nil || !bytes.Equal(ev.Sealed, wire) {
		t.Fatalf("%+v %v", ev, err)
	}
	for name, parts := range map[string]string{
		"no parts":        `[]`,
		"two parts":       `[{"raw":"` + b64(wire) + `","mediaType":"application/vnd.parley.sealed"},{"raw":"` + b64(wire) + `","mediaType":"application/vnd.parley.sealed"}]`,
		"text part":       `[{"text":"hello"}]`,
		"wrong media":     `[{"raw":"` + b64(wire) + `","mediaType":"text/plain"}]`,
		"not base64":      `[{"raw":"@@","mediaType":"application/vnd.parley.sealed"}]`,
		"empty raw":       `[{"raw":"","mediaType":"application/vnd.parley.sealed"}]`,
		"loose base64":    `[{"raw":"` + strings.TrimRight(b64(wire), "=") + `","mediaType":"application/vnd.parley.sealed"}]`,
		"parts not array": `{"raw":"x"}`,
	} {
		if _, err := ParseEvent(a2a(parts)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v, want ErrFormat", name, err)
		}
	}
	if _, err := ParseEvent(`{"a2a":"1.0","task":7}`); !errors.Is(err, ErrFormat) {
		t.Errorf("task of the wrong type: %v", err)
	}
}

func TestPrekeyBlobRoundTripAndStrictness(t *testing.T) {
	s := signedPrekey(t)
	blob := EncodePrekey(s)
	got, err := DecodePrekey(blob)
	if err != nil || !bytes.Equal(EncodePrekey(got), blob) || got.ID != s.ID || !bytes.Equal(got.PublicKey, s.PublicKey) || !bytes.Equal(got.Signature, s.Signature) ||
		got.Tenant != "t1" || got.DeviceID != "dev-b" || got.CallerDeviceID != "dev-a" || got.BindingVersion != 4 || !got.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	flip := func(i int) []byte { b := bytes.Clone(blob); b[i] ^= 1; return b }
	bad := map[string][]byte{
		"empty":        nil,
		"only a sig":   make([]byte, 64),
		"truncated":    blob[:len(blob)-65],
		"trailing":     append(append(bytes.Clone(blob[:len(blob)-64]), 0), blob[len(blob)-64:]...),
		"wrong label":  flip(5),
		"short key":    bytes.Join([][]byte{blob[:20], blob[21:]}, nil),
		"huge":         make([]byte, MaxPrekeyBlob+1),
		"wrong id len": nil,
	}
	delete(bad, "wrong id len")
	for name, b := range bad {
		if _, err := DecodePrekey(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v, want ErrFormat", name, err)
		}
	}
	// A key of another length encodes consistently but is not an X25519 key.
	for _, n := range []int{31, 33} {
		odd := *s
		odd.PublicKey = bytes.Repeat([]byte{1}, n)
		if _, err := DecodePrekey(EncodePrekey(&odd)); !errors.Is(err, ErrFormat) {
			t.Errorf("a %d-byte key: %v", n, err)
		}
	}
	// A prekey whose id is not 16 bytes, built by hand.
	enc := s.Encode()
	i := bytes.Index(enc, s.ID[:])
	short := append(append(bytes.Clone(enc[:i-4]), 0, 0, 0, 15), enc[i:i+15]...)
	short = append(short, enc[i+16:]...)
	if _, err := DecodePrekey(append(short, s.Signature...)); !errors.Is(err, ErrFormat) {
		t.Errorf("short id: %v", err)
	}
}

func TestInnerRoundTrip(t *testing.T) {
	s := signedPrekey(t)
	for _, next := range []*prekey.Signed{nil, s} {
		p := PackInner(next, []byte("content"))
		got, c, err := UnpackInner(p)
		if err != nil || string(c) != "content" || (next == nil) != (got == nil) {
			t.Fatalf("%v %q %v", got, c, err)
		}
		if next != nil && !bytes.Equal(EncodePrekey(got), EncodePrekey(next)) {
			t.Fatal("next-key changed")
		}
	}
	if _, c, err := UnpackInner(PackInner(nil, nil)); err != nil || len(c) != 0 {
		t.Fatalf("empty content: %q %v", c, err)
	}
	blob := EncodePrekey(s)
	for name, p := range map[string][]byte{
		"empty":         nil,
		"bad flag":      {2, 'x'},
		"short length":  {1, 0, 0},
		"length > data": {1, 0, 0, 1, 0, 1},
		"bad blob":      append([]byte{1, 0, 0, 0, 3}, 1, 2, 3),
		"blob cut":      append([]byte{1, 0, 0, byte(len(blob) >> 8), byte(len(blob))}, blob[:10]...),
	} {
		if _, _, err := UnpackInner(p); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v, want ErrFormat", name, err)
		}
	}
}

func TestValidID(t *testing.T) {
	for id, ok := range map[string]bool{"a": true, "dev-1_X": true, strings.Repeat("a", 64): true, "": false, strings.Repeat("a", 65): false, "a b": false, "a/b": false, "é": false} {
		if ValidID(id) != ok {
			t.Errorf("ValidID(%q) = %v", id, !ok)
		}
	}
}

// Every limit is exact: a value of exactly the limit is accepted and one more is not.
func TestLimitsAreExact(t *testing.T) {
	exp := time.UnixMilli(1_800_000_900_000)
	nonce := bytes.Repeat([]byte{7}, MaxNonce)
	blob := bytes.Repeat([]byte{9}, MaxPrekeyBlob)
	req, err := RequestPrekey("r", "d", nonce, exp)
	if err != nil {
		t.Fatalf("a nonce of exactly %d bytes: %v", MaxNonce, err)
	}
	rep, err := ReplyPrekey("r", "d", blob)
	if err != nil {
		t.Fatalf("a blob of exactly %d bytes: %v", MaxPrekeyBlob, err)
	}
	asEvent := func(f string) string { return strings.Replace(f, `"to":`, `"from":`, 1) }
	if ev, err := ParseEvent(asEvent(req)); err != nil || !bytes.Equal(ev.Relay.Nonce, nonce) {
		t.Fatalf("parse a %d-byte nonce: %v", MaxNonce, err)
	}
	if ev, err := ParseEvent(asEvent(rep)); err != nil || !bytes.Equal(ev.Relay.Prekey, blob) {
		t.Fatalf("parse a %d-byte blob: %v", MaxPrekeyBlob, err)
	}
	// Zero is not a time, and zero is a wait.
	if _, err := RequestPrekey("r", "d", nonce, time.UnixMilli(0)); !errors.Is(err, ErrFormat) {
		t.Errorf("expiry 0: %v", err)
	}
	if _, err := ParseEvent(`{"t":"prekey_request","id":"r","from":"d","nonce":"AQID","expires_at":0}`); !errors.Is(err, ErrFormat) {
		t.Errorf("expires_at 0: %v", err)
	}
	if _, err := ParseEvent(`{"t":"prekey_request","id":"r","from":"d","nonce":"AQID","expires_at":1}`); err != nil {
		t.Errorf("expires_at 1: %v", err)
	}
	if ev, err := ParseEvent(`{"t":"prekey_refused","id":"r","from":"d","reason":"offline","retry_after_ms":0}`); err != nil || ev.Relay.RetryAfter != 0 {
		t.Errorf("a wait of 0: %v", err)
	}
	// A whole event of exactly the tunnel's frame limit parses; one byte more does not.
	ok := a2a(`[{"raw":"` + b64([]byte("sealed envelope bytes!")) + `","mediaType":"application/vnd.parley.sealed"}]`)
	atLimit := ok + strings.Repeat(" ", MaxEventBytes-len(ok))
	if _, err := ParseEvent(atLimit); err != nil {
		t.Errorf("an event of exactly %d bytes: %v", MaxEventBytes, err)
	}
	if _, err := ParseEvent(atLimit + " "); !errors.Is(err, ErrFormat) {
		t.Errorf("an event one byte over: %v", err)
	}
}

// Pinned so a changed limit is a deliberate, reviewed edit (these expressions have no statement for mutation
// testing to cover; see tests/coverage/README.md).
func TestConstantsArePinned(t *testing.T) {
	if MaxNonce != 32 || MaxPrekeyBlob != 1024 || MaxEventBytes != 1048576 || MaxRetryAfterMS != 86400000 || SealedMediaType != "application/vnd.parley.sealed" {
		t.Fatalf("%d %d %d %q", MaxNonce, MaxPrekeyBlob, MaxEventBytes, SealedMediaType)
	}
}

// encoding/json keeps the last of duplicate keys and matches names without
// regard to case; a frame with either has a second spelling, so it is refused.
func TestParseEventRefusesDuplicateAndMiscasedKeys(t *testing.T) {
	nonce := b64([]byte("n0n"))
	req := func(extra string) string {
		return `{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":1` + extra + `}`
	}
	if _, err := ParseEvent(req("")); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{
		req(`,"id":"r2"`),
		req(`,"ID":"r2"`),
		`{"T":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":1}`,
		`{"t":"prekey_request","Id":"r1","from":"dev-a","nonce":"` + nonce + `","expires_at":1}`,
		`{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + nonce + `","Expires_At":1}`,
		`{"a2a":"1.0","a2a":"2.0"}`,
		`{"A2A":"1.0"}`,
		`{"a2a":"1.0","task":{"status":{"message":{"parts":[{"raw":"c2VhbGVk","mediaType":"application/vnd.parley.sealed","Raw":"eA=="}]}}}}`,
		`{"a2a":"1.0","task":{"status":{"message":{"parts":[{"raw":"c2VhbGVk","mediaType":"application/vnd.parley.sealed"}]},"Message":{}}}}`,
		`{"a2a":"1.0","x":[{"y":1,"y":2}]}`,
		`{"a2a":"1.0","x":{"k":1,"K":2}}`,
		`{"t":"prekey_request",`,
		`[`,
		``,
	} {
		if _, err := ParseEvent(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err=%v, want ErrFormat", b, err)
		}
	}
	// Keys this package does not read may differ in case, and arrays nest.
	ok := a2a(`[{"raw":"c2VhbGVk","mediaType":"application/vnd.parley.sealed"}]`)
	ok = strings.Replace(ok, `{"a2a"`, `{"extra":[[{"Y":1,"y2":2}],{}],"a2a"`, 1)
	if _, err := ParseEvent(ok); err != nil {
		t.Errorf("benign extra keys refused: %v", err)
	}
}

func TestParseEventNestingIsBounded(t *testing.T) {
	deep := func(n int) string {
		return strings.Replace(a2a(`[{"raw":"c2VhbGVk","mediaType":"application/vnd.parley.sealed"}]`), `{"a2a"`,
			`{"x":`+strings.Repeat("[", n)+strings.Repeat("]", n)+`,"a2a"`, 1)
	}
	if _, err := ParseEvent(deep(maxDepth - 1)); err != nil {
		t.Errorf("depth %d refused: %v", maxDepth-1, err)
	}
	if _, err := ParseEvent(deep(maxDepth)); !errors.Is(err, ErrFormat) {
		t.Errorf("depth %d: err=%v, want ErrFormat", maxDepth, err)
	}
	if _, err := ParseEvent(deep(100000)); !errors.Is(err, ErrFormat) {
		t.Errorf("very deep: err=%v, want ErrFormat", err)
	}
}

// The base64 decoder skips CR and LF; the frame must still have one spelling.
func TestBase64WithLineBreaksIsRefused(t *testing.T) {
	for _, n := range []string{"AQID\n", "AQ\nID", "AQ\r\nID", "\nAQID"} {
		b := `{"t":"prekey_request","id":"r1","from":"dev-a","nonce":"` + strings.NewReplacer("\n", `\n`, "\r", `\r`).Replace(n) + `","expires_at":1}`
		if _, err := ParseEvent(b); !errors.Is(err, ErrFormat) {
			t.Errorf("%q: err=%v, want ErrFormat", n, err)
		}
	}
}

// retry_after_ms becomes a Duration: a huge value must not wrap.
func TestRetryAfterCannotOverflow(t *testing.T) {
	refused := func(ms string) string {
		return `{"t":"prekey_refused","id":"r1","from":"dev-b","reason":"rate_limited","retry_after_ms":` + ms + `}`
	}
	max := strconv.FormatInt(MaxRetryAfterMS, 10)
	ev, err := ParseEvent(refused(max))
	if err != nil || ev.Relay.RetryAfter != 24*time.Hour {
		t.Fatalf("at the cap: %v %+v", err, ev.Relay)
	}
	for _, ms := range []string{strconv.FormatInt(MaxRetryAfterMS+1, 10), "9223372036854775807", "9223372036854"} {
		if _, err := ParseEvent(refused(ms)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err=%v, want ErrFormat", ms, err)
		}
	}
}

func TestDecodePrekeyBoundsInputBeforeParsing(t *testing.T) {
	if _, err := DecodePrekey(make([]byte, MaxPrekeyBlob+1)); !errors.Is(err, ErrFormat) {
		t.Errorf("oversize blob: %v", err)
	}
	// A length prefix that wraps a 32-bit or 64-bit sum is only a short read.
	for _, p := range [][]byte{{0xff, 0xff, 0xff, 0xff}, {0xff, 0xff, 0xff, 0xff, 1, 2, 3}, {0x80, 0, 0, 0}} {
		if _, err := DecodePrekey(p); !errors.Is(err, ErrFormat) {
			t.Errorf("% x: %v", p, err)
		}
		if _, _, err := UnpackInner(append([]byte{1}, p...)); !errors.Is(err, ErrFormat) {
			t.Errorf("inner % x: %v", p, err)
		}
	}
}

// A prekey blob of exactly the cap is accepted; one byte more is not.
func TestDecodePrekeyAtTheCap(t *testing.T) {
	s := signedPrekey(t)
	s.Tenant = strings.Repeat("t", len(s.Tenant)+MaxPrekeyBlob-len(EncodePrekey(s)))
	blob := EncodePrekey(s)
	if len(blob) != MaxPrekeyBlob {
		t.Fatalf("setup: %d bytes", len(blob))
	}
	if _, err := DecodePrekey(blob); err != nil {
		t.Fatalf("blob at the cap: %v", err)
	}
	if _, err := DecodePrekey(append(blob, 0)); !errors.Is(err, ErrFormat) {
		t.Fatalf("one over the cap: %v", err)
	}
}

// The wire-format doc and the code agree byte for byte: every vector in the doc
// is what the code produces (and parses back).
func TestDocVectorsMatchTheCode(t *testing.T) {
	raw, err := os.ReadFile("../../specs/parley-mvp/message-pipeline.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	req, _ := RequestPrekey("r1", "dev-b", []byte{1, 2, 3}, time.UnixMilli(1800000900000))
	rep, _ := ReplyPrekey("r1", "dev-a", []byte{9, 8})
	ref, _ := RefusePrekey("r1", "dev-a")
	for name, want := range map[string]string{"request": req, "reply": rep, "refuse": ref, "inner": "006869"} {
		if !strings.Contains(doc, "<!-- vector:"+name+" -->\n`"+want) {
			t.Errorf("doc vector %q is not %s", name, want)
		}
	}
	if next, c, err := UnpackInner([]byte{0, 'h', 'i'}); err != nil || next != nil || string(c) != "hi" {
		t.Errorf("inner vector: %v %v %q", err, next, c)
	}
}
