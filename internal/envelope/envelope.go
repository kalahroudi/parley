// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package envelope is Parley's crypto module for task messages: HPKE sealing
// to a one-time prekey plus an Ed25519-signed transcript. One fixed suite
// (DHKEM X25519, HKDF-SHA256, ChaCha20-Poly1305), no negotiation.
//
// The HPKE info and aad are the SHA-256 of the encoded header, so the
// ciphertext only opens under the header it was sealed with. The signature
// covers the encoded header and the hash of the encapsulated key and
// ciphertext, in both directions, so authentication never rests on DH.
package envelope

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const (
	label = "parley/msg/v1"

	// Suite ids from RFC 9180: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
	kemID  uint16 = 0x0020
	kdfID  uint16 = 0x0001
	aeadID uint16 = 0x0003

	TaskIDSize = 16
	KeySize    = 32
	HashSize   = sha256.Size
)

var (
	ErrInvalid      = errors.New("envelope: missing or malformed field")
	ErrMalformed    = errors.New("envelope: cannot parse")
	ErrBadSignature = errors.New("envelope: signature does not verify")
	ErrOpen         = errors.New("envelope: cannot open ciphertext")
)

// Type is the message type; it is signed, so the gateway's plaintext state
// code is only a hint.
type Type uint8

const (
	TypeTask Type = iota + 1
	TypeStatus
	TypeInputRequired
	TypeResult
	TypeError
	TypeCancel
)

// Header is everything in the signed transcript except the ciphertext hash.
type Header struct {
	Tenant         string
	SenderDevice   string
	SenderKeyID    string
	BindingVersion uint64
	TargetDevice   string
	PrekeyID       string
	TaskID         [TaskIDSize]byte
	ContextID      string
	Seq            uint64
	Type           Type
	IssuedAt       time.Time
	Expiry         time.Time
	RPK            []byte // reply public key; required on TASK, otherwise empty or 32 bytes
	PrevHash       []byte // hash of the previous message in the task; empty only on TASK
	Prekey         []byte // the signed prekey object; required on TASK, empty otherwise
}

func (h Header) validate() error {
	if h.Tenant == "" || h.SenderDevice == "" || h.SenderKeyID == "" || h.BindingVersion == 0 ||
		h.TargetDevice == "" || h.PrekeyID == "" || h.ContextID == "" ||
		h.Type < TypeTask || h.Type > TypeCancel ||
		h.IssuedAt.IsZero() || h.Expiry.Unix() <= h.IssuedAt.Unix() ||
		(len(h.RPK) != 0 && len(h.RPK) != KeySize) {
		return ErrInvalid
	}
	if h.Type == TypeTask {
		if h.Seq != 0 || len(h.RPK) != KeySize || len(h.PrevHash) != 0 || len(h.Prekey) == 0 {
			return ErrInvalid
		}
	} else if h.Seq == 0 || len(h.PrevHash) != HashSize || len(h.Prekey) != 0 {
		return ErrInvalid
	}
	return nil
}

// Encode is the deterministic encoding: each field length-prefixed or
// fixed-width, times as unix seconds.
func (h Header) Encode() []byte {
	var out []byte
	field := func(p []byte) {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	field([]byte(label))
	out = binary.BigEndian.AppendUint16(out, kemID)
	out = binary.BigEndian.AppendUint16(out, kdfID)
	out = binary.BigEndian.AppendUint16(out, aeadID)
	field([]byte(h.Tenant))
	field([]byte(h.SenderDevice))
	field([]byte(h.SenderKeyID))
	out = binary.BigEndian.AppendUint64(out, h.BindingVersion)
	field([]byte(h.TargetDevice))
	field([]byte(h.PrekeyID))
	field(h.TaskID[:])
	field([]byte(h.ContextID))
	out = binary.BigEndian.AppendUint64(out, h.Seq)
	out = append(out, byte(h.Type))
	out = binary.BigEndian.AppendUint64(out, uint64(h.IssuedAt.Unix()))
	out = binary.BigEndian.AppendUint64(out, uint64(h.Expiry.Unix()))
	field(h.RPK)
	field(h.PrevHash)
	field(h.Prekey)
	return out
}

// Hash is the value used as HPKE info and aad.
func (h Header) Hash() [HashSize]byte { return sha256.Sum256(h.Encode()) }

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n uint64) []byte {
	if r.err != nil || n > uint64(len(r.b)) {
		r.err = ErrMalformed
		return nil
	}
	p := r.b[:n]
	r.b = r.b[n:]
	return p
}

func (r *reader) field() []byte { return r.take(uint64(r.u32())) }
func (r *reader) u8() uint8 {
	if p := r.take(1); p != nil {
		return p[0]
	}
	return 0
}
func (r *reader) u16() uint16 {
	if p := r.take(2); p != nil {
		return binary.BigEndian.Uint16(p)
	}
	return 0
}
func (r *reader) u32() uint32 {
	if p := r.take(4); p != nil {
		return binary.BigEndian.Uint32(p)
	}
	return 0
}
func (r *reader) u64() uint64 {
	if p := r.take(8); p != nil {
		return binary.BigEndian.Uint64(p)
	}
	return 0
}
func (r *reader) str() string { return string(r.field()) }

// bytes copies, so decoded values never alias the input buffer.
func (r *reader) bytes() []byte { return append([]byte(nil), r.field()...) }

func (r *reader) header() Header {
	var h Header
	if string(r.field()) != label || r.u16() != kemID || r.u16() != kdfID || r.u16() != aeadID {
		r.err = ErrMalformed
		return h
	}
	h.Tenant = r.str()
	h.SenderDevice = r.str()
	h.SenderKeyID = r.str()
	h.BindingVersion = r.u64()
	h.TargetDevice = r.str()
	h.PrekeyID = r.str()
	if id := r.field(); len(id) == TaskIDSize {
		copy(h.TaskID[:], id)
	} else {
		r.err = ErrMalformed
	}
	h.ContextID = r.str()
	h.Seq = r.u64()
	h.Type = Type(r.u8())
	h.IssuedAt = time.Unix(int64(r.u64()), 0).UTC()
	h.Expiry = time.Unix(int64(r.u64()), 0).UTC()
	h.RPK = r.bytes()
	h.PrevHash = r.bytes()
	h.Prekey = r.bytes()
	if len(h.RPK) == 0 {
		h.RPK = nil
	}
	if len(h.PrevHash) == 0 {
		h.PrevHash = nil
	}
	if len(h.Prekey) == 0 {
		h.Prekey = nil
	}
	return h
}

// DecodeHeader parses and validates an encoded header, rejecting trailing bytes.
func DecodeHeader(p []byte) (Header, error) {
	r := reader{b: p}
	h := r.header()
	if r.err != nil || len(r.b) != 0 {
		return Header{}, ErrMalformed
	}
	if err := h.validate(); err != nil {
		return Header{}, err
	}
	return h, nil
}

// Message is a sealed, signed task message as it travels through the gateway.
type Message struct {
	Header     Header
	Enc        []byte // HPKE encapsulated key
	Ciphertext []byte
	Signature  []byte
}

func ctHash(enc, ct []byte) [HashSize]byte {
	buf := binary.BigEndian.AppendUint32(nil, uint32(len(enc)))
	buf = append(buf, enc...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(ct)))
	buf = append(buf, ct...)
	return sha256.Sum256(buf)
}

// Transcript is the byte string the sender signs.
func (m *Message) Transcript() []byte {
	h := ctHash(m.Enc, m.Ciphertext)
	return append(m.Header.Encode(), h[:]...)
}

// Seal encrypts plaintext to the recipient's one-time prekey (32-byte X25519
// public key) and signs the transcript with the sender's signing key.
func Seal(sign ed25519.PrivateKey, recipient []byte, h Header, plaintext []byte) (*Message, error) {
	if err := h.validate(); err != nil || len(sign) != ed25519.PrivateKeySize {
		return nil, ErrInvalid
	}
	ecpub, err := ecdh.X25519().NewPublicKey(recipient)
	if err != nil {
		return nil, ErrInvalid
	}
	pk, err := hpke.NewDHKEMPublicKey(ecpub)
	if err != nil {
		return nil, err
	}
	hash := h.Hash()
	enc, s, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), hash[:])
	if err != nil {
		return nil, err
	}
	ct, err := s.Seal(hash[:], plaintext)
	if err != nil {
		return nil, err
	}
	m := &Message{Header: h, Enc: enc, Ciphertext: ct}
	m.Signature = ed25519.Sign(sign, m.Transcript())
	return m, nil
}

// Verify checks the sender's signature over the transcript. The caller is
// responsible for having verified the sender's binding and for matching
// header fields (tenant, target, direction) against its own state.
func (m *Message) Verify(sender ed25519.PublicKey) error {
	if len(sender) != ed25519.PublicKeySize || m.Header.validate() != nil {
		return ErrInvalid
	}
	if !ed25519.Verify(sender, m.Transcript(), m.Signature) {
		return ErrBadSignature
	}
	return nil
}

// Open decrypts with the recipient's X25519 private key (32 bytes). It only
// does the AEAD open; ordering of signature checks and key erasure belongs to
// the receive path.
func (m *Message) Open(recipient []byte) ([]byte, error) {
	if m.Header.validate() != nil {
		return nil, ErrInvalid
	}
	sk, err := hpke.DHKEM(ecdh.X25519()).NewPrivateKey(recipient)
	if err != nil {
		return nil, ErrInvalid
	}
	hash := m.Header.Hash()
	r, err := hpke.NewRecipient(m.Enc, sk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), hash[:])
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := r.Open(hash[:], m.Ciphertext)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// Marshal is the wire encoding: header, enc, ciphertext, signature, each
// length-prefixed.
func (m *Message) Marshal() []byte {
	var out []byte
	for _, p := range [][]byte{m.Header.Encode(), m.Enc, m.Ciphertext, m.Signature} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out
}

// Unmarshal parses a wire message without verifying or decrypting it.
func Unmarshal(p []byte) (*Message, error) {
	r := reader{b: p}
	hb, enc, ct, sig := r.field(), r.bytes(), r.bytes(), r.bytes()
	if r.err != nil || len(r.b) != 0 || len(enc) != KeySize || len(sig) != ed25519.SignatureSize {
		return nil, ErrMalformed
	}
	h, err := DecodeHeader(hb)
	if err != nil {
		return nil, err
	}
	return &Message{Header: h, Enc: enc, Ciphertext: ct, Signature: sig}, nil
}
