// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { DurableObject } from "cloudflare:workers";
import { MAX_CARDS_PER_DEVICE, MAX_GROUPS, MAX_RESULTS, canSee, matches, memberships, validateCard, validateGroup, validateQuery, type Card } from "./acl";
import type { Env } from "./index";
import { cleanText } from "./text";

export const TOKEN_TTL_DEFAULT_MS = 24 * 3600_000;
export const TOKEN_TTL_MAX_MS = 7 * 24 * 3600_000;
export const REQUEST_TTL_MS = 7 * 24 * 3600_000;
export const MAX_PENDING = 200;
export const MAX_PENDING_PER_OWNER = 5;
export const DECIDED_RETENTION_MS = 30 * 24 * 3600_000;

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
  // The root-signed binding the admin's daemon posted after approval. Opaque to
  // the gateway: devices verify it against the pinned root, so a forged or
  // swapped binding is rejected there.
  binding?: SignedBinding;
}

export const MAX_SIGNED_BYTES = 4096;
// The revocation list grows with every revoked device (about 35 bytes each), so
// it gets a larger cap; 64 KiB stays well under the 128 KiB storage value limit.
export const MAX_LIST_BYTES = 65536;

// Opaque signed statements the gateway only relays. Fields the gateway needs for
// routing and monotonicity checks are named; the rest are carried untouched.
export type SignedBinding = { device_id: string; signing_key: string; version: number };
export type SignedList = { tenant: string; version: number };

interface StoredEnrollment extends Enrollment {
  poll_hash: string;
}

interface StoredToken {
  owner: string;
  exp: number;
}

// A published card with the routing facts the gateway derived itself: the
// device is the authenticated caller and the owner comes from its approved
// enrollment, never from the request.
export interface DirectoryEntry extends Card {
  id: string; // `${device_id}:${hash of the lowercased name}`
  device_id: string;
  owner: string;
  published: number;
}

export type DirectoryError = "not_enrolled" | "bad_card" | "secret_detected" | "too_many_cards" | "bad_query" | "bad_group" | "bad_members" | "too_many_groups";

export type EnrollError = "bad_token" | "queue_full" | "owner_full" | "bad_request";

const enc = new TextEncoder();
const hex = (b: ArrayBuffer | Uint8Array) =>
  [...(b instanceof Uint8Array ? b : new Uint8Array(b))].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha256 = async (s: string | Uint8Array) => hex(await crypto.subtle.digest("SHA-256", typeof s === "string" ? enc.encode(s) : s));
const random = (n: number) => hex(crypto.getRandomValues(new Uint8Array(n)));

export { cleanText };

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
    const clean = cleanText(owner, 254);
    if (!clean || !(ttlMs > 0)) return null;
    const exp = Date.now() + Math.min(ttlMs, TOKEN_TTL_MAX_MS);
    const token = `pet_${random(24)}`;
    await this.ctx.storage.put(`tok:${await sha256(token)}`, { owner: clean, exp } satisfies StoredToken);
    await this.schedule(exp);
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
    const name = cleanText(input.name, 100);
    if (!key || !name) return { error: "bad_request" };
    let owner = input.user === undefined ? undefined : cleanText(input.user, 254)?.toLowerCase();
    if (input.user !== undefined && !owner) return { error: "bad_request" };
    let kind: Enrollment["kind"] = "user";
    let tokKey: string | undefined;
    if (input.token !== undefined) {
      kind = "pod";
      tokKey = `tok:${await sha256(input.token)}`;
      const tok = await this.ctx.storage.get<StoredToken>(tokKey);
      if (!tok || tok.exp <= Date.now()) return { error: "bad_token" };
      owner = tok.owner;
    }
    if (!owner) return { error: "bad_request" };
    const queue = await this.pending();
    if (queue.length >= MAX_PENDING) return { error: "queue_full" };
    if (queue.filter((e) => e.owner === owner).length >= MAX_PENDING_PER_OWNER) return { error: "owner_full" };

    const id = random(16);
    const poll = random(24);
    const rec: StoredEnrollment = {
      id,
      owner,
      kind,
      name,
      signing_key: btoa(String.fromCharCode(...key)), // canonical form: atob tolerates whitespace and stray bits
      fingerprint: await sha256(key),
      status: "pending",
      created: Date.now(),
      poll_hash: await sha256(poll),
    };
    // A used token is deleted at once; a missing token is indistinguishable from a bad one.
    if (tokKey) await this.ctx.storage.delete(tokKey);
    await this.ctx.storage.put(`enr:${id}`, rec);
    await this.schedule(rec.created + REQUEST_TTL_MS);
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
    await this.schedule(rec.decided + DECIDED_RETENTION_MS);
    return strip(rec);
  }

  // Stores the binding the admin's daemon signed for an approved device. A
  // higher version replaces a lower one; the same version only when identical.
  async putBinding(id: string, b: SignedBinding): Promise<Enrollment | "not_found" | "not_approved" | "mismatch" | "rollback"> {
    const rec = await this.ctx.storage.get<StoredEnrollment>(`enr:${id}`);
    if (!rec) return "not_found";
    if (rec.status !== "approved") return "not_approved";
    if (b.signing_key !== rec.signing_key || b.device_id !== id) return "mismatch"; // the device id is the request id
    if (rec.binding) {
      if (b.device_id !== rec.binding.device_id) return "mismatch";
      if (b.version < rec.binding.version) return "rollback";
      if (b.version === rec.binding.version && JSON.stringify(b) !== JSON.stringify(rec.binding)) return "rollback";
    }
    rec.binding = b;
    await this.ctx.storage.put(`enr:${id}`, rec);
    return strip(rec);
  }

  // The signed revocation list is public and signed by the root holder's daemon;
  // the gateway stores the newest and only relays it. It refuses a lower
  // version, or a different list at the same version (advisory: daemons check too).
  async putRevocations(l: SignedList): Promise<"ok" | "rollback"> {
    const cur = await this.ctx.storage.get<SignedList>("revocations");
    if (cur && (l.version < cur.version || (l.version === cur.version && JSON.stringify(l) !== JSON.stringify(cur)))) return "rollback";
    await this.ctx.storage.put("revocations", l);
    return "ok";
  }

  async revocations(): Promise<SignedList | null> {
    return (await this.ctx.storage.get<SignedList>("revocations")) ?? null;
  }

  // The owner of an enrolled device: its approved enrollment with a root-signed
  // binding. Anything else (unknown, pending, rejected, unbound) is not enrolled.
  private async ownerOf(device: string): Promise<string | null> {
    const rec = await this.ctx.storage.get<StoredEnrollment>(`enr:${device}`);
    return rec && rec.status === "approved" && rec.binding ? rec.owner.toLowerCase() : null;
  }

  // Publishes (or replaces, by name) a card for the calling device. The secrets
  // lint runs here: the gateway cannot read task content, only these plaintext cards.
  async publishCard(device: string, raw: unknown): Promise<{ id: string } | { error: DirectoryError; field?: string }> {
    const owner = await this.ownerOf(device);
    if (!owner) return { error: "not_enrolled" };
    const v = validateCard(raw);
    if ("error" in v) return v;
    const id = `${device}:${(await sha256(v.card.name.toLowerCase())).slice(0, 16)}`;
    const mine = await this.ctx.storage.list({ prefix: `card:${device}:` });
    if (!mine.has(`card:${id}`) && mine.size >= MAX_CARDS_PER_DEVICE) return { error: "too_many_cards" };
    await this.ctx.storage.put(`card:${id}`, { ...v.card, id, device_id: device, owner, published: Date.now() } satisfies DirectoryEntry);
    return { id };
  }

  async removeCard(device: string, id: string): Promise<boolean> {
    if (!id.startsWith(`${device}:`)) return false; // only the publishing device
    return this.ctx.storage.delete(`card:${id}`);
  }

  private async viewerGroups(viewer: string) {
    const all = await this.ctx.storage.list<{ members: string[] }>({ prefix: "grp:" });
    return memberships([...all].map(([k, g]) => [k.slice(4), g.members]), viewer);
  }

  // find_agents: the cards the calling device's owner may see, filtered by name,
  // description and tag. Cards the viewer may not see are not mentioned.
  async find(device: string, rawQuery?: unknown): Promise<{ agents: DirectoryEntry[] } | { error: DirectoryError }> {
    const viewer = await this.ownerOf(device);
    if (!viewer) return { error: "not_enrolled" };
    const q = validateQuery(rawQuery);
    if (!q) return { error: "bad_query" };
    const groups = await this.viewerGroups(viewer);
    const all = await this.ctx.storage.list<DirectoryEntry>({ prefix: "card:" });
    const agents = [...all.values()]
      .filter((c) => canSee(c, c.owner, viewer, groups) && matches(c, q))
      .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id))
      .slice(0, MAX_RESULTS);
    return { agents };
  }

  // The card the calling device may send to, or null. Unknown, hidden and
  // not-permitted are the same answer. (The daemon still checks its allowlist.)
  async resolve(device: string, id: string): Promise<DirectoryEntry | null> {
    const viewer = await this.ownerOf(device);
    if (!viewer) return null;
    const c = await this.ctx.storage.get<DirectoryEntry>(`card:${id}`);
    return c && canSee(c, c.owner, viewer, await this.viewerGroups(viewer)) ? c : null;
  }

  // Groups are managed by the admin; membership is by identity (email or named
  // service owner). Names are plaintext metadata.
  async putGroup(name: unknown, members: unknown): Promise<{ name: string; members: string[] } | { error: DirectoryError }> {
    const g = validateGroup(name, members);
    if ("error" in g) return g;
    if (!(await this.ctx.storage.get(`grp:${g.name}`)) && (await this.ctx.storage.list({ prefix: "grp:" })).size >= MAX_GROUPS) return { error: "too_many_groups" };
    await this.ctx.storage.put(`grp:${g.name}`, { members: g.members });
    return g;
  }

  async deleteGroup(name: string): Promise<boolean> {
    return this.ctx.storage.delete(`grp:${name.toLowerCase()}`);
  }

  async groups(): Promise<{ name: string; members: string[] }[]> {
    const all = await this.ctx.storage.list<{ members: string[] }>({ prefix: "grp:" });
    return [...all].map(([k, g]) => ({ name: k.slice(4), members: g.members }));
  }

  // Keep the earliest wake-up needed to purge records.
  private async schedule(at: number) {
    const cur = await this.ctx.storage.getAlarm();
    if (cur === null || at < cur) await this.ctx.storage.setAlarm(at);
  }

  // Purges expired tokens, expired pending requests and decided records past
  // retention, then re-arms for the next one still due.
  async alarm() {
    const now = Date.now();
    let next: number | undefined;
    const due = async (k: string, at: number) => {
      if (at <= now) await this.ctx.storage.delete(k);
      else if (next === undefined || at < next) next = at;
    };
    for (const [k, r] of await this.ctx.storage.list<StoredEnrollment>({ prefix: "enr:" })) {
      await due(k, r.status === "pending" ? r.created + REQUEST_TTL_MS : (r.decided ?? r.created) + DECIDED_RETENTION_MS);
    }
    for (const [k, t] of await this.ctx.storage.list<StoredToken>({ prefix: "tok:" })) await due(k, t.exp);
    if (next !== undefined) await this.ctx.storage.setAlarm(next);
  }

  // The requesting device polls with the secret it was handed at request time.
  async status(id: string, poll: string): Promise<Enrollment | null> {
    const rec = await this.ctx.storage.get<StoredEnrollment>(`enr:${id}`);
    if (!rec || !timingSafeEqual(rec.poll_hash, await sha256(poll))) return null;
    // An expired pending request can no longer be decided; do not report it as pending forever.
    if (rec.status === "pending" && rec.created + REQUEST_TTL_MS <= Date.now()) return null;
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
