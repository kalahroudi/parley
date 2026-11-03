// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Tier 1 (plan.md coverage policy): what the gateway checks about a sealed A2A
// part before it relays it. A part is the base64 of one envelope wire message
// (internal/envelope Marshal: header, enc, ciphertext, signature, each with a
// 4-byte length). The gateway cannot open it or check the signature (it holds
// no keys); it reads only the plaintext routing header, which the sender signs,
// and checks it agrees with what the JSON-RPC request claims, so the gateway's
// hints cannot drift from the signed message. The daemons check the signature,
// binding and every field again; this file only keeps the relay honest and
// bounded.
//
// Nothing here allocates from a length the sender supplied until that length
// has been checked against what is actually there: sizes are tested before any
// slice, and slices are views, not copies.

export const SEALED_MEDIA_TYPE = "application/vnd.parley.sealed";

// The signed message types (internal/envelope Type), by number.
export const SIGNED_TYPE = { TASK: 1, STATUS: 2, INPUT_REQUIRED: 3, RESULT: 4, ERROR: 5, CANCEL: 6, REPLY: 7 } as const;
export type SignedKind = keyof typeof SIGNED_TYPE;

const LABEL = "parley/msg/v1";
const SUITE = [0x0020, 0x0001, 0x0003]; // HPKE KEM, KDF, AEAD ids (RFC 9180)
const KEY_SIZE = 32;
const SIG_SIZE = 64;
const TASK_ID_SIZE = 16;
export const MIN_BUCKET = 4096;
// The largest plaintext bucket whose frame still fits one tunnel frame (1 MiB)
// after base64 and JSON. Bigger content travels as an encrypted file.
export const MAX_BUCKET = 1 << 19;
const TAG = 16; // AEAD tag: ciphertext = bucket + tag
const MAX_FIELD = 1 << 16;
const MAX_HEADER = 1 << 14; // real headers are under 1 KiB (the prekey object is the largest field); this keeps every accepted part deliverable in one frame
const MAX_WIRE = 4 * 4 + MAX_HEADER + KEY_SIZE + MAX_BUCKET + TAG + SIG_SIZE; // upper bound, header fields at their caps
export const MAX_RAW_CHARS = Math.ceil(MAX_WIRE / 3) * 4;

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export interface Shape {
  kind: SignedKind;
  tenant: string;
  sender: string;
  target: string;
  context: string;
  taskId: string; // lowercase hex of the 16-byte task id
  seq: number;
  bucket: number; // padded plaintext size; the ciphertext is this plus the AEAD tag
}

// A reader that never throws on short data and never reads past it: a read that runs off
// the end moves the position past the end (so `left` goes negative), and an oversized length or
// a number past 2^53 sets `bad`; the caller checks `bad` and `left` once at the end (as
// internal/envelope's reader does).
// Only a name that is not UTF-8 throws, and parseWire catches that.
class Reader {
  bad = false;
  private i = 0;
  constructor(private readonly b: Uint8Array) {}
  get left(): number {
    return this.b.length - this.i;
  }
  take(n: number): Uint8Array {
    const out = this.b.subarray(this.i, this.i + n);
    this.i += n;
    return out;
  }
  num(n: 1 | 2 | 4 | 8): number {
    let v = 0n;
    for (const x of this.take(n)) v = (v << 8n) | BigInt(x);
    this.bad ||= v > BigInt(Number.MAX_SAFE_INTEGER);
    return Number(v);
  }
  // A 4-byte length, then that many bytes; the length is held to the cap, and to what remains by the caller's check of `left`.
  field(max = MAX_FIELD): Uint8Array {
    const n = this.num(4);
    this.bad ||= n > max;
    return this.take(n);
  }
  str(): string {
    return utf8.decode(this.field());
  }
}

const hex = (p: Uint8Array) => Array.from(p, (x) => x.toString(16).padStart(2, "0")).join("");

// Reads the plaintext header of an envelope wire message. Returns null for anything the
// daemon's own parser would refuse (internal/envelope Unmarshal and Header.validate),
// for a ciphertext that is not an exact padding bucket plus the tag, and for trailing bytes.
export function parseWire(wire: Uint8Array): Shape | null {
  const outer = new Reader(wire);
  const hb = outer.field(MAX_HEADER);
  const enc = outer.field();
  const ct = outer.field(MAX_BUCKET + TAG);
  const sig = outer.field();
  if (outer.bad || enc.length !== KEY_SIZE || sig.length !== SIG_SIZE || outer.left !== 0) return null;
  const bucket = ct.length - TAG;
  if (bucket < MIN_BUCKET || (bucket & (bucket - 1)) !== 0) return null;

  try {
    return parseHeader(hb, bucket);
  } catch {
    return null; // a name that is not UTF-8
  }
}

function parseHeader(hb: Uint8Array, bucket: number): Shape | null {
  const r = new Reader(hb);
  const label = r.field();
  const suite = [r.num(2), r.num(2), r.num(2)];
  const tenant = r.str();
  const sender = r.str();
  const keyId = r.str();
  const version = r.num(8);
  const target = r.str();
  const prekeyId = r.str();
  const task = r.field();
  const context = r.str();
  const seq = r.num(8);
  const type = r.num(1);
  const issued = r.num(8);
  const expiry = r.num(8);
  const rpk = r.field();
  const prev = r.field();
  const prekey = r.field();
  if (r.bad || r.left !== 0) return null;
  if (label.length !== LABEL.length || !label.every((c, i) => c === LABEL.charCodeAt(i)) || !SUITE.every((id, i) => suite[i] === id)) return null;
  if (!tenant || !sender || !keyId || !version || !target || !prekeyId || !context || task.length !== TASK_ID_SIZE || expiry <= issued) return null;
  if (rpk.length !== 0 && rpk.length !== KEY_SIZE) return null;
  const kind = (Object.keys(SIGNED_TYPE) as SignedKind[]).find((k) => SIGNED_TYPE[k] === type);
  if (!kind) return null;
  // The same rules as Header.validate: a TASK opens the chain, everything else continues it.
  if (kind === "TASK" ? seq !== 0 || rpk.length !== KEY_SIZE || prev.length !== 0 || prekey.length === 0 : seq === 0 || prev.length !== 32 || prekey.length !== 0) return null;
  return { kind, tenant, sender, target, context, taskId: hex(task), seq, bucket };
}

// The bytes of base64 text that is exactly what btoa writes for them, or null. atob alone forgives
// whitespace and stray padding bits, so one wire message could have many texts.
function canonical(raw: string): string | null {
  try {
    const bin = atob(raw);
    return btoa(bin) === raw ? bin : null;
  } catch {
    return null;
  }
}

// The one part of a sealed message: exactly {raw, mediaType}, base64 that is
// canonical (so one wire form has one text form), no longer than the largest
// frame allows, and a valid envelope. The text length is checked before decoding.
export function parseSealedPart(p: unknown): { raw: string; shape: Shape } | null {
  if (typeof p !== "object" || p === null || Array.isArray(p)) return null;
  const o = p as Record<string, unknown>;
  if (!Object.keys(o).every((k) => k === "raw" || k === "mediaType")) return null;
  const raw = o.raw;
  if (o.mediaType !== SEALED_MEDIA_TYPE || typeof raw !== "string" || raw.length > MAX_RAW_CHARS) return null;
  const bin = canonical(raw);
  if (bin === null) return null;
  const shape = parseWire(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  return shape && { raw, shape };
}
