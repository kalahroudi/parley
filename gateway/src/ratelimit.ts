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

export type Scope = "task" | "message" | "find";

// Per caller device: a bot doing real work never meets them, a loop or flood does within seconds.
export const POLICIES: Readonly<Record<Scope, Policy>> = {
  task: { capacity: 20, refillPerSec: 0.5 }, // new tasks: 20 at once, then 30 a minute
  message: { capacity: 100, refillPerSec: 5 }, // status, replies, cancels, GetTask
  find: { capacity: 30, refillPerSec: 1 }, // directory searches
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
