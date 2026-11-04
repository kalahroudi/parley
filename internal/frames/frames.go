// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package frames is the daemon's side of what crosses the tunnel and the
// sealed payloads inside it. Everything here is parsed from bytes an attacker
// (the gateway, or a malicious peer) may control, so every parser is strict:
// unknown fields, non-canonical base64, oversize values and trailing bytes are
// errors, and an error never carries the input.
//
// Three formats:
//
//   - Relay frames: the prekey request and its answer, which the gateway relays
//     between two live devices (gateway/src/protocol.ts is the other side). The
//     gateway puts the authenticated sender in `from`; a daemon sends `to`.
//   - Gateway events: either a relay frame or an A2A task event whose one part
//     is a sealed envelope (gateway/src/a2a.ts, eventBody).
//   - Sealed payloads: the signed prekey object (the blob carried in a TASK
//     header) and the inner plaintext, which is a next-key flag, an optional
//     signed next-key for the peer's follow-up, and the content.
//
// Nothing in this package decides trust. A parsed prekey or event is only a
// claim until the caller verifies it against a root-signed binding.
package frames

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/kalahroudi/parley/internal/prekey"
)

// Limits. A relay frame is a few hundred bytes; the caps keep a hostile one small.
const (
	MaxNonce      = 32
	MaxPrekeyBlob = 1 << 10
	// MaxEventBytes is the tunnel's frame limit (internal/tunnel maxFrameBytes).
	MaxEventBytes = 1 << 20
	// SealedMediaType marks the one part of a message: an envelope wire message.
	SealedMediaType = "application/vnd.parley.sealed"

	sigSize = ed25519.SignatureSize
	idSize  = 16
	keySize = 32
)

var (
	// ErrFormat means the input is not a well-formed frame, event, blob or payload.
	ErrFormat = errors.New("frames: malformed")
	// ErrUnsupported means a well-formed JSON event of a kind this daemon does not handle.
	ErrUnsupported = errors.New("frames: unsupported event")
)

var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidID reports whether s is a device or request id the gateway accepts.
func ValidID(s string) bool { return idRe.MatchString(s) }

// Relay frame kinds.
const (
	KindPrekeyRequest = "prekey_request"
	KindPrekeyReply   = "prekey_reply"
	KindPrekeyRefused = "prekey_refused"
)

// Refusal reasons the gateway or a target may give. The text is fixed: a
// reason never says why a target refused (so a caller learns nothing about its
// allowlist).
const (
	ReasonRefused     = "refused"
	ReasonOffline     = "offline"
	ReasonRateLimited = "rate_limited"
)

// Relay is a relay frame as a daemon receives it from the gateway. Peer is the
// gateway's account of who sent it: the other end's device id.
type Relay struct {
	Kind       string
	ID         string // the request id, chosen by the requester
	Peer       string
	Nonce      []byte    // request only
	TaskExpiry time.Time // request only
	Prekey     []byte    // reply only: the signed prekey blob (see EncodePrekey)
	Reason     string    // refusal only
	RetryAfter time.Duration
}

type wireRelay struct {
	T          string `json:"t"`
	ID         string `json:"id"`
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
	Prekey     string `json:"prekey,omitempty"`
	Reason     string `json:"reason,omitempty"`
	RetryAfter int64  `json:"retry_after_ms,omitempty"`
}

// canonical b64 decodes standard base64 and accepts only the one text that
// encodes the bytes, so a frame has one wire form.
func canonical(s string, max int) ([]byte, error) {
	if base64.StdEncoding.EncodedLen(max) < len(s) {
		return nil, ErrFormat
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) > max {
		return nil, ErrFormat
	}
	return b, nil
}

// strictJSON decodes one value and refuses unknown fields. ParseEvent has
// already run json.Unmarshal over the same body, which refuses trailing data.
func strictJSON(body string, v any) error {
	d := json.NewDecoder(bytes.NewReader([]byte(body)))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrFormat
	}
	return nil
}

// RequestPrekey is the frame a caller sends to ask `to` for a one-time prekey.
func RequestPrekey(id, to string, nonce []byte, taskExpiry time.Time) (string, error) {
	if !ValidID(id) || !ValidID(to) || len(nonce) == 0 || len(nonce) > MaxNonce || taskExpiry.UnixMilli() <= 0 {
		return "", ErrFormat
	}
	return marshal(wireRelay{T: KindPrekeyRequest, ID: id, To: to, Nonce: base64.StdEncoding.EncodeToString(nonce), ExpiresAt: taskExpiry.UnixMilli()}), nil
}

// ReplyPrekey is the frame a target sends back with the signed prekey blob.
func ReplyPrekey(id, to string, blob []byte) (string, error) {
	if !ValidID(id) || !ValidID(to) || len(blob) == 0 || len(blob) > MaxPrekeyBlob {
		return "", ErrFormat
	}
	return marshal(wireRelay{T: KindPrekeyReply, ID: id, To: to, Prekey: base64.StdEncoding.EncodeToString(blob)}), nil
}

// RefusePrekey is the frame a target sends when it will not issue a prekey.
func RefusePrekey(id, to string) (string, error) {
	if !ValidID(id) || !ValidID(to) {
		return "", ErrFormat
	}
	return marshal(wireRelay{T: KindPrekeyRefused, ID: id, To: to}), nil
}

func marshal(w wireRelay) string {
	b, _ := json.Marshal(w) // strings and integers only: it always marshals
	return string(b)
}

func parseRelay(body string) (*Relay, error) {
	var w wireRelay
	if err := strictJSON(body, &w); err != nil {
		return nil, err
	}
	if !ValidID(w.ID) || !ValidID(w.From) || w.To != "" {
		return nil, ErrFormat
	}
	r := &Relay{Kind: w.T, ID: w.ID, Peer: w.From}
	var err error
	switch w.T {
	case KindPrekeyRequest:
		if w.Prekey != "" || w.Reason != "" || w.RetryAfter != 0 || w.ExpiresAt <= 0 {
			return nil, ErrFormat
		}
		if r.Nonce, err = canonical(w.Nonce, MaxNonce); err != nil || len(r.Nonce) == 0 {
			return nil, ErrFormat
		}
		r.TaskExpiry = time.UnixMilli(w.ExpiresAt)
	case KindPrekeyReply:
		if w.Nonce != "" || w.Reason != "" || w.RetryAfter != 0 || w.ExpiresAt != 0 {
			return nil, ErrFormat
		}
		if r.Prekey, err = canonical(w.Prekey, MaxPrekeyBlob); err != nil || len(r.Prekey) == 0 {
			return nil, ErrFormat
		}
	case KindPrekeyRefused:
		if w.Nonce != "" || w.Prekey != "" || w.ExpiresAt != 0 || w.RetryAfter < 0 {
			return nil, ErrFormat
		}
		r.Reason = w.Reason
		if r.Reason != ReasonRefused && r.Reason != ReasonOffline && r.Reason != ReasonRateLimited {
			return nil, ErrFormat
		}
		r.RetryAfter = time.Duration(w.RetryAfter) * time.Millisecond
	default:
		return nil, ErrFormat
	}
	return r, nil
}

// Event is one gateway event: a relay frame or a sealed message. Exactly one
// field is set.
type Event struct {
	Relay  *Relay
	Sealed []byte // an envelope wire message, still sealed
}

type a2aEvent struct {
	A2A  string `json:"a2a"`
	Task struct {
		Status struct {
			Message struct {
				Parts []struct {
					Raw       string `json:"raw"`
					MediaType string `json:"mediaType"`
				} `json:"parts"`
			} `json:"message"`
		} `json:"status"`
	} `json:"task"`
}

// ParseEvent classifies a tunnel event body. The A2A wrapper is the gateway's
// and may carry fields this daemon ignores (state, ids, hints): none of them is
// trusted, because the signed envelope is the truth.
func ParseEvent(body string) (Event, error) {
	if len(body) > MaxEventBytes {
		return Event{}, ErrFormat
	}
	var probe struct {
		T   string `json:"t"`
		A2A string `json:"a2a"`
	}
	if err := json.Unmarshal([]byte(body), &probe); err != nil {
		return Event{}, ErrFormat
	}
	if probe.T != "" {
		r, err := parseRelay(body)
		return Event{Relay: r}, err
	}
	if probe.A2A != "1.0" {
		return Event{}, ErrUnsupported
	}
	var e a2aEvent
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		return Event{}, ErrFormat
	}
	parts := e.Task.Status.Message.Parts
	if len(parts) != 1 || parts[0].MediaType != SealedMediaType {
		return Event{}, ErrFormat
	}
	wire, err := canonical(parts[0].Raw, MaxEventBytes)
	if err != nil || len(wire) == 0 {
		return Event{}, ErrFormat
	}
	return Event{Sealed: wire}, nil
}

// EncodePrekey is the deterministic form of a signed prekey: its signed
// encoding followed by the signature. It is what a TASK header carries and
// what a prekey reply relays.
func EncodePrekey(s *prekey.Signed) []byte { return append(s.Encode(), s.Signature...) }

// DecodePrekey reverses EncodePrekey and rejects anything it could not have
// produced (so one prekey has one encoding). It does not check the signature.
// It reads no more than len(p) bytes; callers bound p.
func DecodePrekey(p []byte) (*prekey.Signed, error) {
	r := reader{b: p}
	r.field() // label and suite: the re-encoding check below pins both
	r.field()
	s := &prekey.Signed{}
	s.Tenant, s.DeviceID, s.SigningKeyID = string(r.field()), string(r.field()), string(r.field())
	s.BindingVersion = r.u64()
	id := r.field()
	s.PublicKey = bytes.Clone(r.field())
	s.CallerDeviceID = string(r.field())
	s.Nonce = bytes.Clone(r.field())
	s.CreatedAt = time.Unix(int64(r.u64()), 0).UTC()
	s.ExpiresAt = time.Unix(int64(r.u64()), 0).UTC()
	signed := len(p) - len(r.b)
	s.Signature = bytes.Clone(r.take(sigSize))
	if r.bad {
		return nil, ErrFormat
	}
	if len(r.b) != 0 {
		return nil, ErrFormat // trailing bytes
	}
	if len(s.PublicKey) != keySize {
		return nil, ErrFormat
	}
	copy(s.ID[:], id)
	// Re-encoding must give back the input: that rejects a wrong label or
	// suite, an id that is not 16 bytes (it would be cut or padded) and any
	// other second spelling.
	if !bytes.Equal(s.Encode(), p[:signed]) {
		return nil, ErrFormat
	}
	return s, nil
}

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n uint64) []byte {
	if uint64(len(r.b)) < n {
		r.bad, r.b = true, nil
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) field() []byte {
	h := r.take(4)
	if r.bad {
		return nil
	}
	return r.take(uint64(binary.BigEndian.Uint32(h)))
}

func (r *reader) u64() uint64 {
	h := r.take(8)
	if r.bad {
		return 0
	}
	return binary.BigEndian.Uint64(h)
}

// PackInner builds the plaintext that is padded and sealed: a flag, the signed
// next-key for the peer's follow-up when there is one, then the content.
func PackInner(next *prekey.Signed, content []byte) []byte {
	if next == nil {
		return append([]byte{0}, content...)
	}
	blob := EncodePrekey(next)
	out := binary.BigEndian.AppendUint32([]byte{1}, uint32(len(blob)))
	return append(append(out, blob...), content...)
}

// UnpackInner reverses PackInner. The next-key is returned unverified. The
// content aliases p.
func UnpackInner(p []byte) (next *prekey.Signed, content []byte, err error) {
	if len(p) == 0 || p[0] > 1 {
		return nil, nil, ErrFormat
	}
	if p[0] == 0 {
		return nil, p[1:], nil
	}
	r := reader{b: p[1:]}
	blob := r.field()
	if r.bad {
		return nil, nil, ErrFormat
	}
	if next, err = DecodePrekey(blob); err != nil {
		return nil, nil, err
	}
	return next, r.b, nil
}
