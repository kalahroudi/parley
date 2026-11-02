// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type keys struct {
	sign       ed25519.PrivateKey
	prekeyPriv []byte
	prekeyPub  []byte
}

func newKeys(t *testing.T) keys {
	t.Helper()
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keys{sign, k.Bytes(), k.PublicKey().Bytes()}
}

func taskHeader() Header {
	h := Header{
		Tenant: "tenant-1", SenderDevice: "dev-a", SenderKeyID: "key-1", BindingVersion: 3,
		TargetDevice: "dev-b", PrekeyID: "pk-1", ContextID: "ctx-1",
		Type: TypeTask, IssuedAt: t0, Expiry: t0.Add(15 * time.Minute),
		RPK: bytes.Repeat([]byte{7}, KeySize), Prekey: []byte("signed-prekey-object"),
	}
	copy(h.TaskID[:], bytes.Repeat([]byte{9}, TaskIDSize))
	return h
}

func replyHeader() Header {
	h := taskHeader()
	h.Type, h.Seq = TypeResult, 1
	h.Prekey = nil
	h.PrevHash = bytes.Repeat([]byte{5}, HashSize)
	return h
}

func TestRoundTrip(t *testing.T) {
	k := newKeys(t)
	for _, h := range []Header{taskHeader(), replyHeader()} {
		m, err := Seal(k.sign, k.prekeyPub, h, []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Unmarshal(m.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		if err := got.Verify(k.sign.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
		pt, err := got.Open(k.prekeyPriv)
		if err != nil || string(pt) != "hello" {
			t.Fatalf("open: %q %v", pt, err)
		}
	}
}

func TestSealIsRandomized(t *testing.T) {
	k := newKeys(t)
	a, _ := Seal(k.sign, k.prekeyPub, taskHeader(), []byte("x"))
	b, _ := Seal(k.sign, k.prekeyPub, taskHeader(), []byte("x"))
	if bytes.Equal(a.Enc, b.Enc) || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("two seals share an encapsulated key or ciphertext")
	}
}

// Every header field is bound to the ciphertext (via info/aad) and the signature.
func TestHeaderTamperingRejected(t *testing.T) {
	k := newKeys(t)
	pub := k.sign.Public().(ed25519.PublicKey)
	muts := map[string]func(*Header){
		"tenant":   func(h *Header) { h.Tenant = "tenant-2" },
		"sender":   func(h *Header) { h.SenderDevice = "dev-x" },
		"keyid":    func(h *Header) { h.SenderKeyID = "key-2" },
		"version":  func(h *Header) { h.BindingVersion++ },
		"target":   func(h *Header) { h.TargetDevice = "dev-x" },
		"prekeyid": func(h *Header) { h.PrekeyID = "pk-2" },
		"taskid":   func(h *Header) { h.TaskID[0] ^= 1 },
		"context":  func(h *Header) { h.ContextID = "ctx-2" },
		"seq":      func(h *Header) { h.Seq++ },
		"issued":   func(h *Header) { h.IssuedAt = h.IssuedAt.Add(-time.Second) },
		"expiry":   func(h *Header) { h.Expiry = h.Expiry.Add(time.Hour) },
		"rpk":      func(h *Header) { h.RPK = bytes.Repeat([]byte{8}, KeySize) },
		"prekey":   func(h *Header) { h.Prekey = []byte("other") },
		"type":     func(h *Header) { h.Type = TypeCancel },
	}
	for name, mut := range muts {
		t.Run(name, func(t *testing.T) {
			m, err := Seal(k.sign, k.prekeyPub, taskHeader(), []byte("p"))
			if err != nil {
				t.Fatal(err)
			}
			mut(&m.Header)
			if name == "seq" || name == "type" { // keep it structurally valid for the checks below
				m.Header.Type, m.Header.PrevHash = TypeResult, bytes.Repeat([]byte{5}, HashSize)
				m.Header.Prekey, m.Header.Seq = nil, 1
			}
			if err := m.Verify(pub); err == nil {
				t.Fatal("signature accepted")
			}
			if _, err := m.Open(k.prekeyPriv); err == nil {
				t.Fatal("ciphertext opened under a different header")
			}
		})
	}
}

func TestPrevHashTampering(t *testing.T) {
	k := newKeys(t)
	m, _ := Seal(k.sign, k.prekeyPub, replyHeader(), []byte("p"))
	m.Header.PrevHash = bytes.Repeat([]byte{6}, HashSize)
	if m.Verify(k.sign.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("swapped prev hash accepted")
	}
	if _, err := m.Open(k.prekeyPriv); err == nil {
		t.Fatal("opened with swapped prev hash")
	}
}

func TestCiphertextAndKeyChecks(t *testing.T) {
	k, other := newKeys(t), newKeys(t)
	pub := k.sign.Public().(ed25519.PublicKey)
	m, _ := Seal(k.sign, k.prekeyPub, taskHeader(), []byte("p"))

	if _, err := m.Open(other.prekeyPriv); !errors.Is(err, ErrOpen) {
		t.Fatalf("wrong prekey: %v", err)
	}
	if err := m.Verify(other.sign.Public().(ed25519.PublicKey)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong signer: %v", err)
	}
	c := *m
	c.Ciphertext = append([]byte(nil), m.Ciphertext...)
	c.Ciphertext[0] ^= 1
	if !errors.Is(c.Verify(pub), ErrBadSignature) {
		t.Fatal("tampered ciphertext verified")
	}
	if _, err := c.Open(k.prekeyPriv); !errors.Is(err, ErrOpen) {
		t.Fatalf("tampered ciphertext opened: %v", err)
	}
	c = *m
	c.Enc = append([]byte(nil), m.Enc...)
	c.Enc[0] ^= 1
	if !errors.Is(c.Verify(pub), ErrBadSignature) {
		t.Fatal("tampered enc verified")
	}
	if _, err := c.Open(k.prekeyPriv); !errors.Is(err, ErrOpen) {
		t.Fatalf("tampered enc opened: %v", err)
	}
	c = *m
	c.Enc = c.Enc[:10]
	if _, err := c.Open(k.prekeyPriv); !errors.Is(err, ErrOpen) {
		t.Fatalf("short enc: %v", err)
	}
}

func TestInputValidation(t *testing.T) {
	k := newKeys(t)
	bad := map[string]func(*Header){
		"tenant":      func(h *Header) { h.Tenant = "" },
		"sender":      func(h *Header) { h.SenderDevice = "" },
		"keyid":       func(h *Header) { h.SenderKeyID = "" },
		"version":     func(h *Header) { h.BindingVersion = 0 },
		"target":      func(h *Header) { h.TargetDevice = "" },
		"prekeyid":    func(h *Header) { h.PrekeyID = "" },
		"context":     func(h *Header) { h.ContextID = "" },
		"type0":       func(h *Header) { h.Type = 0 },
		"type7":       func(h *Header) { h.Type = 7 },
		"issued":      func(h *Header) { h.IssuedAt = time.Time{} },
		"expiry":      func(h *Header) { h.Expiry = h.IssuedAt },
		"rpk-len":     func(h *Header) { h.RPK = []byte{1} },
		"task-seq":    func(h *Header) { h.Seq = 1 },
		"task-no-rpk": func(h *Header) { h.RPK = nil },
		"task-prev":   func(h *Header) { h.PrevHash = make([]byte, HashSize) },
		"task-no-pk":  func(h *Header) { h.Prekey = nil },
	}
	for name, mut := range bad {
		h := taskHeader()
		mut(&h)
		if _, err := Seal(k.sign, k.prekeyPub, h, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	reply := map[string]func(*Header){
		"seq0":    func(h *Header) { h.Seq = 0 },
		"no-prev": func(h *Header) { h.PrevHash = nil },
		"short":   func(h *Header) { h.PrevHash = []byte{1} },
		"prekey":  func(h *Header) { h.Prekey = []byte{1} },
	}
	for name, mut := range reply {
		h := replyHeader()
		mut(&h)
		if _, err := Seal(k.sign, k.prekeyPub, h, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("reply %s: %v", name, err)
		}
	}
	if _, err := Seal(k.sign[:10], k.prekeyPub, taskHeader(), nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("short signing key: %v", err)
	}
	if _, err := Seal(k.sign, []byte{1}, taskHeader(), nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("short recipient: %v", err)
	}
	// An all-zero X25519 public key is a low-order point; HPKE must refuse it.
	if _, err := Seal(k.sign, make([]byte, KeySize), taskHeader(), nil); err == nil {
		t.Error("low-order recipient accepted")
	}

	m, _ := Seal(k.sign, k.prekeyPub, taskHeader(), nil)
	if m.Verify(ed25519.PublicKey{1, 2, 3}) == nil {
		t.Error("short verify key accepted")
	}
	if _, err := m.Open([]byte{1}); !errors.Is(err, ErrInvalid) {
		t.Errorf("short open key: %v", err)
	}
	m.Header.Tenant = ""
	if m.Verify(k.sign.Public().(ed25519.PublicKey)) == nil {
		t.Error("invalid header verified")
	}
	if _, err := m.Open(k.prekeyPriv); !errors.Is(err, ErrInvalid) {
		t.Errorf("invalid header opened: %v", err)
	}
}

func TestUnmarshalRejectsMalformed(t *testing.T) {
	k := newKeys(t)
	m, _ := Seal(k.sign, k.prekeyPub, taskHeader(), []byte("p"))
	wire := m.Marshal()

	for i := 0; i < len(wire); i++ {
		if _, err := Unmarshal(wire[:i]); err == nil {
			t.Fatalf("truncation at %d accepted", i)
		}
	}
	if _, err := Unmarshal(append(append([]byte(nil), wire...), 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	// Corrupt each header byte: it must never both parse and keep the original signature valid.
	hdr := m.Header.Encode()
	for i := range hdr {
		c := append([]byte(nil), hdr...)
		c[i] ^= 0xff
		if h, err := DecodeHeader(c); err == nil && bytes.Equal(h.Encode(), hdr) {
			t.Fatalf("non-canonical header accepted at byte %d", i)
		}
	}
	// Bad suite id, bad label, huge length prefix.
	for _, off := range []int{4, 4 + len(label) + 1, 0} {
		c := append([]byte(nil), hdr...)
		c[off] ^= 0xff
		if _, err := DecodeHeader(c); err == nil {
			t.Fatalf("corrupt byte %d accepted", off)
		}
	}
	// Header that parses but fails validation.
	h := taskHeader()
	h.Tenant = ""
	if _, err := DecodeHeader(h.Encode()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid decoded header: %v", err)
	}
	// Wrong enc / signature size.
	short := *m
	short.Enc = short.Enc[:8]
	if _, err := Unmarshal(short.Marshal()); err == nil {
		t.Fatal("short enc accepted")
	}
	short = *m
	short.Signature = short.Signature[:8]
	if _, err := Unmarshal(short.Marshal()); err == nil {
		t.Fatal("short signature accepted")
	}
	// Bad task id length.
	bad := append([]byte(nil), hdr...)
	// task id field length prefix sits after fixed fields; find it by search.
	idx := bytes.Index(bad, append([]byte{0, 0, 0, TaskIDSize}, bytes.Repeat([]byte{9}, TaskIDSize)...))
	bad[idx+3] = 15
	if _, err := DecodeHeader(bad); err == nil {
		t.Fatal("bad task id length accepted")
	}
}

// Moving bytes between adjacent fields must change the encoding.
func TestEncodingUnambiguous(t *testing.T) {
	a, b := taskHeader(), taskHeader()
	a.Tenant, a.SenderDevice = "ab", "c"
	b.Tenant, b.SenderDevice = "a", "bc"
	if bytes.Equal(a.Encode(), b.Encode()) {
		t.Fatal("field boundary ambiguous")
	}
}

func TestEmptyOptionalFieldsDecodeAsNil(t *testing.T) {
	h := replyHeader()
	got, err := DecodeHeader(h.Encode())
	if err != nil || got.Prekey != nil || got.RPK == nil {
		t.Fatalf("%+v %v", got, err)
	}
	h.RPK = nil
	got, err = DecodeHeader(h.Encode())
	if err != nil || got.RPK != nil {
		t.Fatalf("%+v %v", got, err)
	}
}

// testdata/vectors.json is published: other implementations check their
// encoding, hashes, signatures and decryption against it. Changing it is a
// wire-format change. Regenerate with PARLEY_UPDATE_VECTORS=1.
type vector struct {
	Name       string `json:"name"`
	Header     string `json:"header"`
	HeaderHash string `json:"header_hash"`
	Plaintext  string `json:"plaintext"`
	Enc        string `json:"enc"`
	Ciphertext string `json:"ciphertext"`
	Transcript string `json:"transcript"`
	Signature  string `json:"signature"`
	Message    string `json:"message"`
}

type vectorFile struct {
	Description        string   `json:"description"`
	SenderSeed         string   `json:"sender_signing_seed"`
	SenderPublicKey    string   `json:"sender_signing_public_key"`
	RecipientPrekeyKey string   `json:"recipient_prekey_private"`
	RecipientPrekeyPub string   `json:"recipient_prekey_public"`
	Vectors            []vector `json:"vectors"`
}

func vectorKeys(t testing.TB) (ed25519.PrivateKey, []byte, []byte) {
	t.Helper()
	sign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x22}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return sign, k.Bytes(), k.PublicKey().Bytes()
}

func vectorHeaders() map[string]Header {
	task := taskHeader()
	task.Prekey = bytes.Repeat([]byte{0xab}, 40)
	reply := replyHeader()
	reply.Type, reply.Seq = TypeResult, 1
	hash := task.Hash()
	reply.PrevHash = hash[:]
	reply.PrekeyID = "pk-1"
	status := reply
	status.Type, status.Seq = TypeStatus, 2
	return map[string]Header{"task": task, "result": reply, "status-empty-rpk": func() Header { s := status; s.RPK = nil; return s }()}
}

var vectorOrder = []string{"task", "result", "status-empty-rpk"}

func TestPublishedVectors(t *testing.T) {
	sign, priv, pub := vectorKeys(t)
	if os.Getenv("PARLEY_UPDATE_VECTORS") == "1" {
		f := vectorFile{
			Description: "Parley message v1 vectors. header = Header.Encode(); header_hash = SHA-256(header) = HPKE info and aad; " +
				"suite = DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305 base mode; transcript = header || SHA-256(u32(len enc)||enc||u32(len ct)||ct); " +
				"signature = Ed25519(sender, transcript); message = Message.Marshal(). enc and ciphertext are one sample sealing (HPKE is randomized).",
			SenderSeed:         hex.EncodeToString(bytes.Repeat([]byte{0x11}, ed25519.SeedSize)),
			SenderPublicKey:    hex.EncodeToString(sign.Public().(ed25519.PublicKey)),
			RecipientPrekeyKey: hex.EncodeToString(priv),
			RecipientPrekeyPub: hex.EncodeToString(pub),
		}
		hs := vectorHeaders()
		for _, name := range vectorOrder {
			h, pt := hs[name], []byte("plaintext for "+name)
			m, err := Seal(sign, pub, h, pt)
			if err != nil {
				t.Fatal(err)
			}
			hash := h.Hash()
			f.Vectors = append(f.Vectors, vector{name, hex.EncodeToString(h.Encode()), hex.EncodeToString(hash[:]),
				hex.EncodeToString(pt), hex.EncodeToString(m.Enc), hex.EncodeToString(m.Ciphertext),
				hex.EncodeToString(m.Transcript()), hex.EncodeToString(m.Signature), hex.EncodeToString(m.Marshal())})
		}
		out, _ := json.MarshalIndent(f, "", "  ")
		if err := os.WriteFile("testdata/vectors.json", append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.SenderPublicKey != hex.EncodeToString(sign.Public().(ed25519.PublicKey)) || f.RecipientPrekeyKey != hex.EncodeToString(priv) {
		t.Fatal("vector keys changed")
	}
	if len(f.Vectors) != len(vectorOrder) {
		t.Fatal("vectors missing")
	}
	hs := vectorHeaders()
	for i, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.Name != vectorOrder[i] {
				t.Fatalf("vector %d is %s", i, v.Name)
			}
			h := hs[v.Name]
			if got := hex.EncodeToString(h.Encode()); got != v.Header {
				t.Fatalf("header encoding changed:\n got %s\nwant %s", got, v.Header)
			}
			hash := h.Hash()
			if hex.EncodeToString(hash[:]) != v.HeaderHash {
				t.Fatal("header hash changed")
			}
			m, err := Unmarshal(unhex(t, v.Message))
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(m.Enc) != v.Enc || hex.EncodeToString(m.Ciphertext) != v.Ciphertext ||
				hex.EncodeToString(m.Transcript()) != v.Transcript || hex.EncodeToString(m.Signature) != v.Signature {
				t.Fatal("message does not match its parts")
			}
			// Ed25519 is deterministic: re-signing must reproduce the published signature.
			if got := hex.EncodeToString(ed25519.Sign(sign, m.Transcript())); got != v.Signature {
				t.Fatalf("signature changed:\n got %s\nwant %s", got, v.Signature)
			}
			if err := m.Verify(sign.Public().(ed25519.PublicKey)); err != nil {
				t.Fatal(err)
			}
			pt, err := m.Open(priv)
			if err != nil || hex.EncodeToString(pt) != v.Plaintext {
				t.Fatalf("open: %x %v", pt, err)
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

func TestDecodeHeaderTruncated(t *testing.T) {
	hdr := taskHeader().Encode()
	for i := 0; i < len(hdr); i++ {
		if _, err := DecodeHeader(hdr[:i]); !errors.Is(err, ErrMalformed) {
			t.Fatalf("truncation at %d: %v", i, err)
		}
	}
	// A well-framed message whose header is malformed is rejected by Unmarshal.
	k := newKeys(t)
	m, _ := Seal(k.sign, k.prekeyPub, taskHeader(), nil)
	var wire []byte
	for _, p := range [][]byte{hdr[:20], m.Enc, m.Ciphertext, m.Signature} {
		wire = append(wire, 0, 0, 0, byte(len(p)))
		wire = append(wire, p...)
	}
	if _, err := Unmarshal(wire); err == nil {
		t.Fatal("malformed header accepted")
	}
}

// Times are encoded as whole seconds, so a header that Seal accepts must
// still decode: an expiry less than a second after issue is rejected up front.
func TestSubSecondExpiryRejected(t *testing.T) {
	k := newKeys(t)
	h := taskHeader()
	h.IssuedAt = t0.Add(100 * time.Millisecond)
	h.Expiry = t0.Add(900 * time.Millisecond)
	if _, err := Seal(k.sign, k.prekeyPub, h, []byte("x")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Seal accepted sub-second validity window: %v", err)
	}
	h.Expiry = t0.Add(1500 * time.Millisecond)
	m, err := Seal(k.sign, k.prekeyPub, h, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unmarshal(m.Marshal()); err != nil {
		t.Fatalf("sealed message does not round-trip: %v", err)
	}
}

func TestFieldAndPayloadLimits(t *testing.T) {
	k := newKeys(t)
	h := taskHeader()
	h.ContextID = string(make([]byte, MaxFieldSize+1))
	if _, err := Seal(k.sign, k.prekeyPub, h, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize field: %v", err)
	}
	h = taskHeader()
	h.Prekey = make([]byte, MaxFieldSize+1)
	if _, err := DecodeHeader(h.Encode()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize prekey decoded: %v", err)
	}
	if _, err := Seal(k.sign, k.prekeyPub, taskHeader(), make([]byte, MaxCiphertextSize)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize plaintext: %v", err)
	}
	m, err := Seal(k.sign, k.prekeyPub, taskHeader(), make([]byte, MaxCiphertextSize-ciphertextOverhead))
	if err != nil {
		t.Fatalf("largest payload: %v", err)
	}
	if _, err := Unmarshal(m.Marshal()); err != nil {
		t.Fatal(err)
	}
	// The limits are inclusive: the largest ciphertext and the longest field are valid.
	if err := m.Verify(k.sign.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("largest ciphertext rejected by Verify: %v", err)
	}
	h = taskHeader()
	h.ContextID = string(bytes.Repeat([]byte{'c'}, MaxFieldSize))
	if _, err := Seal(k.sign, k.prekeyPub, h, nil); err != nil {
		t.Fatalf("longest field rejected: %v", err)
	}
	h = replyHeader()
	h.Type = TypeCancel // the last valid message type
	if _, err := Seal(k.sign, k.prekeyPub, h, nil); err != nil {
		t.Fatalf("cancel rejected: %v", err)
	}
	m.Ciphertext = append(m.Ciphertext, 0)
	if _, err := Unmarshal(m.Marshal()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversize ciphertext unmarshalled: %v", err)
	}
	if err := m.Verify(k.sign.Public().(ed25519.PublicKey)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize ciphertext verified: %v", err)
	}
}

func TestVerifyRejectsBadEncLength(t *testing.T) {
	k := newKeys(t)
	m, _ := Seal(k.sign, k.prekeyPub, taskHeader(), []byte("x"))
	m.Enc = m.Enc[:KeySize-1]
	if err := m.Verify(k.sign.Public().(ed25519.PublicKey)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short enc: %v", err)
	}
}

// X25519 points of low order give an all-zero DH output; they must be refused
// when sealing to them and when used as an encapsulated key.
func TestLowOrderPoints(t *testing.T) {
	k := newKeys(t)
	pub := k.sign.Public().(ed25519.PublicKey)
	zero := make([]byte, KeySize)
	one := make([]byte, KeySize)
	one[0] = 1
	for name, p := range map[string][]byte{"zero": zero, "one": one} {
		if _, err := Seal(k.sign, p, taskHeader(), []byte("x")); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s recipient: %v", name, err)
		}
		m, err := Seal(k.sign, k.prekeyPub, taskHeader(), []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		m.Enc = p
		m.Signature = ed25519.Sign(k.sign, m.Transcript())
		if err := m.Verify(pub); err != nil {
			t.Fatal(err)
		}
		if pt, err := m.Open(k.prekeyPriv); !errors.Is(err, ErrOpen) || pt != nil {
			t.Fatalf("%s enc opened: %x %v", name, pt, err)
		}
	}
	if _, err := Seal(k.sign, []byte{1}, taskHeader(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short recipient: %v", err)
	}
}

func TestVerifyAndOpen(t *testing.T) {
	k := newKeys(t)
	pub := k.sign.Public().(ed25519.PublicKey)
	m, err := Seal(k.sign, k.prekeyPub, taskHeader(), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := m.VerifyAndOpen(pub, k.prekeyPriv); err != nil || string(pt) != "hello" {
		t.Fatalf("%q %v", pt, err)
	}
	other := newKeys(t)
	// Wrong sender: rejected before any decryption.
	if pt, err := m.VerifyAndOpen(other.sign.Public().(ed25519.PublicKey), k.prekeyPriv); !errors.Is(err, ErrBadSignature) || pt != nil {
		t.Fatalf("wrong sender: %q %v", pt, err)
	}
	// Right sender, wrong recipient key: signature fine, open fails, no plaintext.
	if pt, err := m.VerifyAndOpen(pub, other.prekeyPriv); !errors.Is(err, ErrOpen) || pt != nil {
		t.Fatalf("wrong recipient: %q %v", pt, err)
	}
	// Valid ciphertext re-signed under a tampered header never opens.
	bad := *m
	bad.Header.ContextID = "other"
	if pt, err := bad.Open(k.prekeyPriv); err == nil || pt != nil {
		t.Fatalf("header swap opened: %q %v", pt, err)
	}
}

// FuzzMessage feeds arbitrary bytes through the whole receive surface. Nothing
// may panic, and plaintext may come back only from a message whose signature
// verifies and whose encoding round-trips exactly.
func FuzzMessage(f *testing.F) {
	sign, priv, pub := vectorKeys(f)
	spub := sign.Public().(ed25519.PublicKey)
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		f.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		f.Fatal(err)
	}
	for _, v := range vf.Vectors {
		b, _ := hex.DecodeString(v.Message)
		f.Add(b)
	}
	for _, h := range []Header{taskHeader(), replyHeader()} {
		m, err := Seal(sign, pub, h, []byte("seed"))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(m.Marshal())
		f.Add(h.Encode())
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if h, err := DecodeHeader(b); err == nil && !bytes.Equal(h.Encode(), b) {
			t.Fatalf("header does not re-encode to its input")
		}
		m, err := Unmarshal(b)
		if err != nil {
			return
		}
		if !bytes.Equal(m.Marshal(), b) {
			t.Fatalf("message does not re-marshal to its input")
		}
		pt, err := m.VerifyAndOpen(spub, priv)
		if err != nil && pt != nil {
			t.Fatal("plaintext returned with an error")
		}
		if pt2, err2 := m.Open(priv); err2 != nil && pt2 != nil {
			t.Fatal("Open returned plaintext with an error")
		}
	})
}
