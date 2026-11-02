// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { DurableObject } from "cloudflare:workers";
import type { Env } from "./index";

export const TOKEN_TTL_DEFAULT_MS = 24 * 3600_000;
export const TOKEN_TTL_MAX_MS = 7 * 24 * 3600_000;
export const REQUEST_TTL_MS = 7 * 24 * 3600_000;
export const MAX_PENDING = 200;

export type EnrollmentStatus = "pending" | "approved" | "rejected";

// Metadata only: who asked, for which device, with which key. No content.
export interface Enrollment {
  id: string;
  owner: string; // user email, or the named service owner for a pod
  kind: "user" | "pod";
  name: string; // device name
  signing_key: string; // base64 Ed25519 public key
  fingerprint: string; // SHA-256 of the key, hex, for the admin to compare
  status: EnrollmentStatus;
  created: number;
  decided?: number;
}

interface StoredEnrollment extends Enrollment {
  poll_hash: string;
}

interface StoredToken {
  owner: string;
  exp: number;
  used?: number;
}

export type EnrollError = "bad_token" | "queue_full" | "bad_request";

const enc = new TextEncoder();
const hex = (b: ArrayBuffer | Uint8Array) =>
  [...(b instanceof Uint8Array ? b : new Uint8Array(b))].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha256 = async (s: string | Uint8Array) => hex(await crypto.subtle.digest("SHA-256", typeof s === "string" ? enc.encode(s) : s));
const random = (n: number) => hex(crypto.getRandomValues(new Uint8Array(n)));

export function decodeKey(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64);
    if (bin.length !== 32) return null;
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

// One Tenant DO per customer (named by tenant id). It holds the enrollment
// tokens (as hashes) and the approval queue. Binding signatures come from the
// admin's daemon, not from here; the gateway only records the decision.
export class Tenant extends DurableObject<Env> {
  // Admin-minted, single-use pod token. The plaintext is returned once and only
  // its hash is stored.
  async mintToken(owner: string, ttlMs = TOKEN_TTL_DEFAULT_MS): Promise<{ token: string; expires_at: number } | null> {
    if (!owner || owner.length > 254 || !(ttlMs > 0)) return null;
    const exp = Date.now() + Math.min(ttlMs, TOKEN_TTL_MAX_MS);
    const token = `pet_${random(24)}`;
    await this.ctx.storage.put(`tok:${await sha256(token)}`, { owner, exp } satisfies StoredToken);
    return { token, expires_at: exp };
  }

  // `user` is the verified identity of an SSO login (interactive enrollment);
  // `token` is a pod token. Exactly one of them applies.
  request(input: { user?: string; token?: string; name: string; signing_key: string }) {
    // Serialized: the token check and its consumption must not interleave with
    // another request using the same token (crypto awaits would let them).
    return this.ctx.blockConcurrencyWhile(() => this.enroll(input));
  }

  private async enroll(
    input: { user?: string; token?: string; name: string; signing_key: string },
  ): Promise<{ id: string; poll: string } | { error: EnrollError }> {
    const key = decodeKey(input.signing_key);
    if (!key || !input.name || input.name.length > 100) return { error: "bad_request" };
    let owner = input.user;
    let kind: Enrollment["kind"] = "user";
    let tokKey: string | undefined;
    if (input.token !== undefined) {
      kind = "pod";
      tokKey = `tok:${await sha256(input.token)}`;
      const tok = await this.ctx.storage.get<StoredToken>(tokKey);
      if (!tok || tok.used || tok.exp <= Date.now()) return { error: "bad_token" };
      owner = tok.owner;
    }
    if (!owner) return { error: "bad_request" };
    if ((await this.pending()).length >= MAX_PENDING) return { error: "queue_full" };

    const id = random(16);
    const poll = random(24);
    const rec: StoredEnrollment = {
      id,
      owner,
      kind,
      name: input.name,
      signing_key: input.signing_key,
      fingerprint: await sha256(key),
      status: "pending",
      created: Date.now(),
      poll_hash: await sha256(poll),
    };
    if (tokKey) await this.ctx.storage.put(tokKey, { ...(await this.ctx.storage.get<StoredToken>(tokKey))!, used: rec.created });
    await this.ctx.storage.put(`enr:${id}`, rec);
    return { id, poll };
  }

  async pending(): Promise<Enrollment[]> {
    const now = Date.now();
    const all = await this.ctx.storage.list<StoredEnrollment>({ prefix: "enr:" });
    const out: Enrollment[] = [];
    for (const [k, r] of all) {
      if (r.status !== "pending") continue;
      if (r.created + REQUEST_TTL_MS <= now) {
        await this.ctx.storage.delete(k);
        continue;
      }
      out.push(strip(r));
    }
    return out.sort((a, b) => a.created - b.created);
  }

  // Idempotent for the same decision; a decided request cannot change sides.
  async decide(id: string, decision: "approved" | "rejected"): Promise<Enrollment | null | "conflict"> {
    const rec = await this.ctx.storage.get<StoredEnrollment>(`enr:${id}`);
    if (!rec || (rec.status === "pending" && rec.created + REQUEST_TTL_MS <= Date.now())) return null;
    if (rec.status !== "pending") return rec.status === decision ? strip(rec) : "conflict";
    rec.status = decision;
    rec.decided = Date.now();
    await this.ctx.storage.put(`enr:${id}`, rec);
    return strip(rec);
  }

  // The requesting device polls with the secret it was handed at request time.
  async status(id: string, poll: string): Promise<Enrollment | null> {
    const rec = await this.ctx.storage.get<StoredEnrollment>(`enr:${id}`);
    if (!rec || !timingSafeEqual(rec.poll_hash, await sha256(poll))) return null;
    return strip(rec);
  }
}

function strip({ poll_hash: _, ...e }: StoredEnrollment): Enrollment {
  return e;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
