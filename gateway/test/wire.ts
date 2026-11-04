// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Builds envelope wire messages the way internal/envelope (Go) encodes them, with
// the ciphertext and signature left as zero bytes: the gateway never opens or
// verifies them, it reads the plaintext header and the sizes. Every field can be
// overridden, so tests can break exactly one thing.

import { SELF, env } from "cloudflare:test";
import { handleA2A } from "../src/a2a";
import { SIGNED_TYPE, type SignedKind } from "../src/parts";

const te = new TextEncoder();
const u = (n: number | bigint, bytes: number) => {
  const out = new Uint8Array(bytes);
  let v = BigInt(n);
  for (let i = bytes - 1; i >= 0; i--, v >>= 8n) out[i] = Number(v & 0xffn);
  return out;
};
const cat = (...ps: Uint8Array[]) => {
  const out = new Uint8Array(ps.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of ps) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
const field = (p: Uint8Array) => cat(u(p.length, 4), p);
const text = (v: string | Uint8Array) => (typeof v === "string" ? te.encode(v) : v);

export interface Header {
  label?: string | Uint8Array;
  suite?: number[];
  tenant?: string | Uint8Array;
  sender?: string | Uint8Array;
  keyId?: string | Uint8Array;
  version?: number | bigint;
  target?: string | Uint8Array;
  prekeyId?: string | Uint8Array;
  task?: Uint8Array;
  context?: string | Uint8Array;
  seq?: number | bigint;
  type?: number;
  issued?: number | bigint;
  expiry?: number | bigint;
  rpk?: Uint8Array;
  prev?: Uint8Array;
  prekey?: Uint8Array;
  trailing?: Uint8Array;
}

export interface Wire {
  header: Header;
  hdrBytes?: Uint8Array; // the header bytes themselves, instead of encoding `header`
  enc?: Uint8Array;
  bucket?: number; // ciphertext = bucket + 16 zero bytes
  ctLen?: number; // or an exact ciphertext length
  ct?: Uint8Array; // bytes to put at the start of the ciphertext
  sig?: Uint8Array;
  trailing?: Uint8Array;
}

export const taskHex = (name: string) => Array.from(taskBytes(name), (x) => x.toString(16).padStart(2, "0")).join("");
// A readable name (at most 16 bytes) as a 16-byte task id.
export function taskBytes(name: string): Uint8Array {
  const out = new Uint8Array(16);
  out.set(te.encode(name).subarray(0, 16));
  return out;
}

export function encodeHeader(h: Header): Uint8Array {
  return cat(
    field(text(h.label ?? "parley/msg/v1")),
    ...(h.suite ?? [0x0020, 0x0001, 0x0003]).map((x) => u(x, 2)),
    field(text(h.tenant ?? "t")),
    field(text(h.sender ?? "alice")),
    field(text(h.keyId ?? "k1")),
    u(h.version ?? 1, 8),
    field(text(h.target ?? "bob")),
    field(text(h.prekeyId ?? "p1")),
    field(h.task ?? taskBytes("tk")),
    field(text(h.context ?? "ctx")),
    u(h.seq ?? 0, 8),
    u(h.type ?? 1, 1),
    u(h.issued ?? 1_000, 8),
    u(h.expiry ?? 2_000, 8),
    field(h.rpk ?? new Uint8Array(0)),
    field(h.prev ?? new Uint8Array(0)),
    field(h.prekey ?? new Uint8Array(0)),
    h.trailing ?? new Uint8Array(0),
  );
}

export function encodeWire(w: Wire): Uint8Array {
  const ct = new Uint8Array(w.ctLen ?? (w.bucket ?? 4096) + 16);
  if (w.ct) ct.set(w.ct);
  return cat(field(w.hdrBytes ?? encodeHeader(w.header)), field(w.enc ?? new Uint8Array(32)), field(ct), field(w.sig ?? new Uint8Array(64)), w.trailing ?? new Uint8Array(0));
}

export function b64(p: Uint8Array): string {
  let s = "";
  for (let i = 0; i < p.length; i += 0x8000) s += String.fromCharCode(...p.subarray(i, i + 0x8000));
  return btoa(s);
}

// A valid header for a message kind, with the fields that kind must or must not carry.
export function header(kind: SignedKind, over: Header = {}): Header {
  const task = kind === "TASK";
  return {
    type: SIGNED_TYPE[kind],
    seq: task ? 0 : 1,
    rpk: task ? new Uint8Array(32) : new Uint8Array(0),
    prev: task ? new Uint8Array(0) : new Uint8Array(32),
    prekey: task ? new Uint8Array(40) : new Uint8Array(0),
    ...over,
  };
}

// Devices have no credential until connect tokens land, so the Worker keeps /a2a
// and /v1/connect closed. Tests stand in for the Worker after it authenticates:
// `Bearer dev:<tenant>:<device>` is resolved here, never by the gateway.
export async function gw(input: string | URL, init?: RequestInit): Promise<Response> {
  const url = new URL(input);
  const h = new Headers(init?.headers);
  const m = /^Bearer dev:([^:]+):([^:]+)$/.exec(h.get("Authorization") ?? "");
  if (m && url.pathname === "/a2a") return handleA2A(new Request(url, init), env, { tenant: m[1]!, device: m[2]! });
  if (m && url.pathname === "/v1/connect") return env.DEVICE.get(env.DEVICE.idFromName(`${m[1]}:${m[2]}`)).fetch("https://do/", { headers: { Upgrade: "websocket" } });
  return SELF.fetch(input, init);
}
