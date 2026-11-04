// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Token-bucket arithmetic for the Tenant DO's rate limits. Pure: the caller
// supplies the clock and keeps the state, so the maths is tested without a
// Durable Object. A bucket holds up to `capacity` tokens and refills at
// `refillPerSec`; each request costs one. A refused request changes nothing, so
// a client that keeps hammering is not pushed further out than the bucket needs.

export interface Policy {
  capacity: number; // burst size, in requests
  refillPerSec: number; // sustained rate
}

export interface Bucket {
  tokens: number;
  at: number; // ms timestamp of `tokens`
}

export type Decision =
  | { ok: true; bucket: Bucket; full_at: number } // full_at: when the bucket is full again (it can then be deleted)
  | { ok: false; retry_after_ms: number };

// "session" is for the session endpoints (/v1/session and its logout) to adopt; "status" is the unauthenticated enrollment poll.
export type Scope = "task" | "message" | "find" | "presence" | "login" | "enroll" | "status" | "session";

// Per caller device (login: per client address). Chosen so a bot doing real work
// never meets them, and a loop or a flood does within seconds.
export const POLICIES: Readonly<Record<Scope, Policy>> = {
  task: { capacity: 20, refillPerSec: 0.5 }, // new tasks: 20 at once, then 30 a minute
  message: { capacity: 100, refillPerSec: 5 }, // status, replies, cancels, GetTask
  find: { capacity: 30, refillPerSec: 1 }, // directory searches
  presence: { capacity: 60, refillPerSec: 2 }, // a waiting sender polls this
  login: { capacity: 10, refillPerSec: 1 / 6 }, // 10 starts, then 10 a minute, per address
  enroll: { capacity: 20, refillPerSec: 1 / 30 }, // enrollment requests (valid or not): per user, or per address for a pod token
  status: { capacity: 30, refillPerSec: 0.5 }, // polling an enrollment decision, per address
  session: { capacity: 30, refillPerSec: 0.5 }, // session and logout calls, per address
};

// A second, tenant-wide counter for scopes where many sources can add up to a
// flood (a botnet of addresses, a runaway fleet). Checked together with the
// per-source one: the request must pass both, and only then is either charged.
export const TENANT_POLICIES: Readonly<Partial<Record<Scope, Policy>>> = {
  task: { capacity: 400, refillPerSec: 10 },
  enroll: { capacity: 60, refillPerSec: 1 },
  status: { capacity: 300, refillPerSec: 10 },
};

// A bucket that was never used starts full. A clock that went backwards refills nothing.
function level(b: Bucket | undefined, now: number, p: Policy): number {
  if (!b) return p.capacity;
  return Math.min(p.capacity, b.tokens + (Math.max(0, now - b.at) / 1000) * p.refillPerSec);
}

export function take(b: Bucket | undefined, now: number, p: Policy): Decision {
  const tokens = level(b, now, p);
  if (tokens < 1) return { ok: false, retry_after_ms: Math.ceil(((1 - tokens) / p.refillPerSec) * 1000) };
  const left = tokens - 1;
  return { ok: true, bucket: { tokens: left, at: now }, full_at: now + Math.ceil(((p.capacity - left) / p.refillPerSec) * 1000) };
}

// The key a source (an address, an email) is counted under: HMAC-SHA256 with a
// salt, cut to 128 bits. The salt is a server secret plus the tenant, so the same
// address has a different key in every tenant, and neither the raw value nor a
// table of hashes of all addresses can be read out of storage.
export async function sourceKey(salt: string, value: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(salt), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(value)));
  return [...mac.slice(0, 16)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// The client address Cloudflare saw; one shared "none" when there is none (not
// possible behind Cloudflare), which is the strictest reading.
export const clientAddress = (req: Request): string => req.headers.get("CF-Connecting-IP") ?? "none";

// The refusal every limited endpoint sends: 429, a Retry-After in whole seconds
// (never 0), and the exact wait. Nothing about the caller.
export function tooMany(retryAfterMs: number): Response {
  return new Response(JSON.stringify({ error: "rate_limited", retry_after_ms: retryAfterMs }), {
    status: 429,
    headers: { "content-type": "application/json", "cache-control": "no-store", "retry-after": String(Math.max(1, Math.ceil(retryAfterMs / 1000))) },
  });
}
