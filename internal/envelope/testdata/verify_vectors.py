#!/usr/bin/env python3
# Independent check of vectors.json. Shares no code with the Go package: it
# parses the header itself, rebuilds the transcript, verifies the Ed25519
# signature and opens the ciphertext with its own RFC 9180 base-mode
# implementation (DHKEM(X25519,HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305).
# Needs: pip install cryptography. Run: python3 verify_vectors.py [vectors.json]
import hashlib, json, struct, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.hmac import HMAC

def hmac(k, m):
    h = HMAC(k, hashes.SHA256()); h.update(m); return h.finalize()
def extract(salt, ikm): return hmac(salt or b"\0" * 32, ikm)
def expand(prk, info, n): return HKDFExpand(hashes.SHA256(), n, info).derive(prk)
def labeled_extract(sid, salt, label, ikm): return extract(salt, b"HPKE-v1" + sid + label + ikm)
def labeled_expand(sid, prk, label, info, n): return expand(prk, struct.pack(">H", n) + b"HPKE-v1" + sid + label + info, n)

KEM, KDF, AEAD = 0x0020, 0x0001, 0x0003

def hpke_open(enc, sk_bytes, info, aad, ct):
    sk = x25519.X25519PrivateKey.from_private_bytes(sk_bytes)
    pkr = sk.public_key().public_bytes_raw()
    dh = sk.exchange(x25519.X25519PublicKey.from_public_bytes(enc))
    ksid = b"KEM" + struct.pack(">H", KEM)
    eae = labeled_extract(ksid, b"", b"eae_prk", dh)
    secret = labeled_expand(ksid, eae, b"shared_secret", enc + pkr, 32)
    sid = b"HPKE" + struct.pack(">HHH", KEM, KDF, AEAD)
    psk_id_hash = labeled_extract(sid, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(sid, b"", b"info_hash", info)
    ctx = b"\0" + psk_id_hash + info_hash
    secret_ = labeled_extract(sid, secret, b"secret", b"")
    key = labeled_expand(sid, secret_, b"key", ctx, 32)
    nonce = labeled_expand(sid, secret_, b"base_nonce", ctx, 12)  # seq 0
    return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)

class R:
    def __init__(s, b): s.b = b
    def take(s, n):
        assert n <= len(s.b), "truncated"; p, s.b = s.b[:n], s.b[n:]; return p
    def u8(s): return s.take(1)[0]
    def u16(s): return struct.unpack(">H", s.take(2))[0]
    def u64(s): return struct.unpack(">Q", s.take(8))[0]
    def field(s): return s.take(struct.unpack(">I", s.take(4))[0])

def parse_header(h):
    r = R(h)
    assert r.field() == b"parley/msg/v1"
    assert (r.u16(), r.u16(), r.u16()) == (KEM, KDF, AEAD)
    f = {}
    for k in ("tenant", "sender_device", "sender_key_id"): f[k] = r.field().decode()
    f["binding_version"] = r.u64()
    for k in ("target_device", "prekey_id"): f[k] = r.field().decode()
    f["task_id"] = r.field(); assert len(f["task_id"]) == 16
    f["context_id"] = r.field().decode()
    f["seq"] = r.u64(); f["type"] = r.u8()
    f["issued_at"] = r.u64(); f["expiry"] = r.u64()
    for k in ("rpk", "prev_hash", "prekey"): f[k] = r.field()
    assert not r.b, "trailing bytes"
    return f

def main(path):
    d = json.load(open(path))
    pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(d["sender_signing_public_key"]))
    assert ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(d["sender_signing_seed"])).public_key().public_bytes_raw() == pub.public_bytes_raw()
    priv = bytes.fromhex(d["recipient_prekey_private"])
    for v in d["vectors"]:
        header, enc, ct = (bytes.fromhex(v[k]) for k in ("header", "enc", "ciphertext"))
        parse_header(header)
        hh = hashlib.sha256(header).digest()
        assert hh.hex() == v["header_hash"], "header hash"
        ctl = hashlib.sha256(struct.pack(">I", len(enc)) + enc + struct.pack(">I", len(ct)) + ct).digest()
        transcript = header + ctl
        assert transcript.hex() == v["transcript"], "transcript"
        pub.verify(bytes.fromhex(v["signature"]), transcript)
        assert hpke_open(enc, priv, hh, hh, ct).hex() == v["plaintext"], "plaintext"
        sig = bytes.fromhex(v["signature"])
        frames = b"".join(struct.pack(">I", len(p)) + p for p in (header, enc, ct, sig))
        assert frames.hex() == v["message"], "message framing"
        print("ok", v["name"])

main(sys.argv[1] if len(sys.argv) > 1 else __file__.rsplit("/", 1)[0] + "/vectors.json" if "/" in __file__ else "vectors.json")
