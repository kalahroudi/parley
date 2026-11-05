// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { DurableObject } from "cloudflare:workers";
import {
  MAX_CARDS_PER_DEVICE,
  MAX_CARDS_PER_TENANT,
  MAX_GROUPS,
  canSee,
  cardKey,
  isCardId,
  isDeviceId,
  matches,
  memberships,
  paginate,
  validateCard,
  validateGroup,
  validateQuery,
  type Card,
  type Page,
} from "./acl";
import { b64bytes, CHALLENGE_TTL_MS, connectMessage, randomChallenge, verifyBinding, verifyEd25519, type ConnectScope } from "./connect";
import type { Env } from "./index";
import { QUEUE_TTL_DEFAULT_MS, QUEUE_TTL_MAX_MS, QUEUE_TTL_MIN_MS, type Retention } from "./task";
import { cleanText } from "./text";

export const TOKEN_TTL_DEFAULT_MS = 24 * 3600_000;
export const TOKEN_TTL_MAX_MS = 7 * 24 * 3600_000;
export const REQUEST_TTL_MS = 7 * 24 * 3600_000;
export const MAX_PENDING = 200;
export const MAX_PENDING_PER_OWNER = 5;
export const DECIDED_RETENTION_MS = 30 * 24 * 3600_000;

// Admin and user sessions (issued after the OIDC callback). Absolute lifetime;
// the secret is stored only as a hash.
export const SESSION_TTL_MS = 8 * 3600_000;
export const MAX_SESSIONS_PER_USER = 5;

// Device connect tokens (src/connect.ts): short-lived, a few per device (a reconnect takes a new one), oldest first out.
// Outstanding challenges are few per device too; the oldest go first.
export const CONNECT_TOKEN_TTL_MS = 5 * 60_000;
export const MAX_CONNECT_TOKENS_PER_DEVICE = 8;
export const MAX_CHALLENGES_PER_DEVICE = 4;
// Anyone with an IdP login can hold a user session, so user sessions are capped per tenant too (oldest go first).
// Admin sessions are never evicted by a flood of user sessions.
export const MAX_USER_SESSIONS = 1000;

export type Role = "admin" | "user";
export interface Session {
  email: string;
  role: Role;
  csrf: string;
  created: number;
  exp: number;
}

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
// not_after is the binding's RFC 3339 expiry; a binding without a readable one opens no connection.
export type SignedBinding = { device_id: string; signing_key: string; version: number; not_after?: string };
export type SignedList = { tenant: string; version: number; revoked?: unknown };

interface StoredEnrollment extends Enrollment {
  poll_hash: string;
}

export const LOGIN_TTL_MS = 10 * 60_000;
export const MAX_PENDING_LOGINS = 100;

interface StoredLogin {
  session_hash: string;
  poll_hash: string;
  code: string;
  exp: number;
  state: "pending" | "authed" | "done";
  email?: string;
  confirm_hash?: string;
}

interface StoredToken {
  owner: string;
  exp: number;
}

// A connect challenge or connect token, each kept by hash until it expires. Tokens also carry what they are bound to.
interface StoredConnect {
  created: number;
  exp: number;
  version?: number;
  scope?: ConnectScope;
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

// Metadata only: what changed and who did it, never member identities or card text.
export interface AuditEvent {
  at: number;
  action: "group.put" | "group.delete" | "card.publish" | "card.remove" | "revocations.put" | "retention.put";
  actor: "admin" | string; // "admin" or a device id
  subject: string; // group name, card id, or list version
  detail?: Record<string, number | string>;
}
export const MAX_AUDIT = 500;

// The device ids a signed revocation list names; anything not a string is ignored.
const revokedOf = (l: { revoked?: unknown } | undefined | null) => new Set(Array.isArray(l?.revoked) ? l.revoked.filter((x): x is string => typeof x === "string") : []);

// The tenant's retention mode (Strict unless the admin chooses Queued) and how
// long Queued keeps an unacknowledged result.
export interface RetentionSettings {
  mode: Retention;
  queue_ttl_ms: number;
}

export type DirectoryError = "bad_retention" | "not_enrolled" | "bad_card" | "secret_detected" | "too_many_cards" | "bad_query" | "bad_group" | "bad_members" | "too_many_groups";

export type EnrollError = "bad_token" | "queue_full" | "owner_full" | "bad_request" | "conflict";

const enc = new TextEncoder();
const hex = (b: ArrayBuffer | Uint8Array) =>
  [...(b instanceof Uint8Array ? b : new Uint8Array(b))].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha256 = async (s: string | Uint8Array) => hex(await crypto.subtle.digest("SHA-256", typeof s === "string" ? enc.encode(s) : s));
const random = (n: number) => hex(crypto.getRandomValues(new Uint8Array(n)));

export { cleanText };

export const tenantStub = (env: Env, tenant: string) => env.TENANT.get(env.TENANT.idFromName(tenant)) as DurableObjectStub<Tenant>;

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

  // Starts a session for a verified login. Only the hash of the returned secret
  // is kept; the oldest sessions of the same user and role beyond the cap go.
  async createSession(email: string, role: Role): Promise<{ secret: string; csrf: string; expires_at: number }> {
    const secret = random(32);
    return { secret, ...(await this.storeSession(email, role, await sha256(secret))) };
  }

  // A device login (src/login.ts): the caller holds the secret and only its hash arrives, so no plaintext is stored
  // or relayed. The hash must be new, or an existing session could be overwritten.
  private async createDeviceSession(email: string, secretHash: string): Promise<boolean> {
    if ((await this.ctx.storage.get(`ses:${secretHash}`)) !== undefined) return false;
    await this.storeSession(email, "user", secretHash);
    return true;
  }

  private async storeSession(email: string, role: Role, secretHash: string): Promise<{ csrf: string; expires_at: number }> {
    const now = Date.now();
    const key = `ses:${secretHash}`;
    const rec: Session = { email, role, csrf: random(16), created: now, exp: now + SESSION_TTL_MS };
    const all = [...(await this.ctx.storage.list<Session>({ prefix: "ses:" }))].sort((a, b) => a[1].created - b[1].created);
    const mine = all.filter(([, s]) => s.email === email && s.role === role);
    const evict = new Set(mine.slice(0, Math.max(0, mine.length - MAX_SESSIONS_PER_USER + 1)).map(([k]) => k));
    const users = all.filter(([k, s]) => s.role === "user" && !evict.has(k));
    if (role === "user") for (const [k] of users.slice(0, Math.max(0, users.length - MAX_USER_SESSIONS + 1))) evict.add(k);
    await Promise.all(this.deleteAll([...evict]));
    await this.ctx.storage.put(key, rec);
    await this.schedule(rec.exp);
    return { csrf: rec.csrf, expires_at: rec.exp };
  }

  // Device logins (`parley-cli login`). The CLI makes the session secret and the poll secret and sends only their
  // hashes. The browser proves who the user is (OIDC) and the user confirms the code the terminal shows, which is what
  // stops someone else's terminal from receiving your session. The session is created at confirmation with the CLI's
  // hash, so the gateway never holds a usable session secret.
  async loginStart(sessionHash: string, pollHash: string): Promise<{ id: string; code: string; expires_at: number } | { error: "bad_request" | "too_many" }> {
    return this.ctx.blockConcurrencyWhile(async () => {
      const hex64 = /^[0-9a-f]{64}$/;
      if (typeof sessionHash !== "string" || typeof pollHash !== "string" || !hex64.test(sessionHash) || !hex64.test(pollHash)) return { error: "bad_request" as const };
      const now = Date.now();
      const live = [...(await this.ctx.storage.list<StoredLogin>({ prefix: "lgn:" })).values()].filter((l) => l.exp > now);
      if (live.length >= MAX_PENDING_LOGINS) return { error: "too_many" as const };
      const id = random(16);
      const code = random(4).toUpperCase().replace(/(.{4})(.{4})/, "$1-$2");
      const exp = now + LOGIN_TTL_MS;
      await this.ctx.storage.put(`lgn:${id}`, { session_hash: sessionHash, poll_hash: pollHash, code, exp, state: "pending" } satisfies StoredLogin);
      await this.schedule(exp);
      return { id, code, expires_at: exp };
    });
  }

  // The browser's OIDC login succeeded for `email`: hands back the code to show and a one-time confirm secret for the
  // page's form (kept as a hash). Once per login.
  async loginAuth(id: string, email: string): Promise<{ code: string; confirm: string } | null> {
    return this.ctx.blockConcurrencyWhile(async () => {
      const l = await this.ctx.storage.get<StoredLogin>(`lgn:${id}`);
      if (!l || l.exp <= Date.now() || l.state !== "pending") return null;
      const confirm = random(16);
      await this.ctx.storage.put(`lgn:${id}`, { ...l, state: "authed", email, confirm_hash: await sha256(confirm) });
      return { code: l.code, confirm };
    });
  }

  async loginConfirm(id: string, confirm: string): Promise<boolean> {
    return this.ctx.blockConcurrencyWhile(async () => {
      const l = await this.ctx.storage.get<StoredLogin>(`lgn:${id}`);
      if (!l || l.exp <= Date.now() || l.state !== "authed" || !l.email || !l.confirm_hash || !timingSafeEqual(l.confirm_hash, await sha256(confirm))) return false;
      if (!(await this.createDeviceSession(l.email, l.session_hash))) return false;
      await this.ctx.storage.put(`lgn:${id}`, { ...l, state: "done", confirm_hash: undefined });
      return true;
    });
  }

  // The CLI asks whether the user confirmed. The answer "done" is given once, and the record goes with it.
  async loginPoll(id: string, poll: string): Promise<"pending" | "done" | null> {
    const l = await this.ctx.storage.get<StoredLogin>(`lgn:${id}`);
    if (!l || l.exp <= Date.now() || !timingSafeEqual(l.poll_hash, await sha256(poll))) return null;
    if (l.state !== "done") return "pending";
    await this.ctx.storage.delete(`lgn:${id}`);
    return "done";
  }

  // Null for an unknown, signed-out or expired session.
  async getSession(secret: string): Promise<Session | null> {
    const k = `ses:${await sha256(secret)}`;
    const rec = await this.ctx.storage.get<Session>(k);
    if (!rec) return null;
    if (rec.exp <= Date.now()) {
      await this.ctx.storage.delete(k);
      return null;
    }
    return rec;
  }

  async endSession(secret: string): Promise<void> {
    await this.ctx.storage.delete(`ses:${await sha256(secret)}`);
  }

  // `user` is the verified identity of an SSO login (interactive enrollment);
  // `token` is a pod token. Exactly one of them applies.
  // A device may choose the request id and poll secret itself (both random, made before it sends anything). Then the
  // request is idempotent: repeating it after a lost reply or a crash returns the same request instead of queueing a
  // second one, and a different key or poll secret under a taken id is a conflict.
  request(input: { user?: string; token?: string; name: string; signing_key: string; id?: string; poll?: string }) {
    // Serialized: the token check and its consumption must not interleave with
    // another request using the same token (crypto awaits would let them).
    return this.ctx.blockConcurrencyWhile(() => this.enroll(input));
  }

  private async enroll(
    input: { user?: string; token?: string; name: string; signing_key: string; id?: string; poll?: string },
  ): Promise<{ id: string; poll: string } | { error: EnrollError }> {
    // Enrollment tolerates pasted whitespace; the stored key is the canonical spelling.
    const key = b64bytes(input.signing_key.replace(/\s/g, ""), 32);
    const name = cleanText(input.name, 100);
    if (!key || !name) return { error: "bad_request" };
    const chosen = input.id !== undefined || input.poll !== undefined;
    if (chosen) {
      if (!/^[0-9a-f]{32}$/.test(input.id ?? "") || !/^[0-9a-f]{48,64}$/.test(input.poll ?? "")) return { error: "bad_request" };
      const prior = await this.ctx.storage.get<StoredEnrollment>(`enr:${input.id}`);
      if (prior) {
        const same = timingSafeEqual(prior.poll_hash, await sha256(input.poll!)) && prior.signing_key === btoa(String.fromCharCode(...key));
        return same ? { id: prior.id, poll: input.poll! } : { error: "conflict" };
      }
    }
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

    const id = chosen ? input.id! : random(16);
    const poll = chosen ? input.poll! : random(24);
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
    if (cur && JSON.stringify(l) === JSON.stringify(cur)) return "ok";
    // A revoked device leaves the directory at once: its cards go in the same
    // commit that records the list, and reads ignore it from then on.
    const revoked = revokedOf(l);
    const cards = await this.ctx.storage.list<DirectoryEntry>({ prefix: "card:", limit: MAX_CARDS_PER_TENANT });
    const doomed = [...cards].filter(([, c]) => revoked.has(c.device_id)).map(([k]) => k);
    await this.commit({ revocations: l }, doomed, {
      action: "revocations.put",
      actor: "admin",
      subject: String(l.version),
      detail: { revoked: revoked.size, cards_removed: doomed.length },
    });
    return "ok";
  }

  async revocations(): Promise<SignedList | null> {
    return (await this.ctx.storage.get<SignedList>("revocations")) ?? null;
  }

  // Devices the root holder has revoked (the `revoked` ids of the newest signed
  // list). The gateway cannot check the signature, but treating a listed device
  // as gone only hides things, so it acts on the list at once.
  private async revokedIds(): Promise<Set<string>> {
    return revokedOf(await this.ctx.storage.get<SignedList>("revocations"));
  }

  // The owner of an enrolled device: its approved enrollment with a root-signed
  // binding, not revoked. Anything else (unknown, pending, rejected, unbound,
  // revoked, or not shaped like a device id) is not enrolled.
  private async ownerOf(device: string): Promise<string | null> {
    if (!isDeviceId(device) || (await this.revokedIds()).has(device)) return null;
    const rec = await this.ctx.storage.get<StoredEnrollment>(`enr:${device}`);
    return rec && rec.status === "approved" && rec.binding ? rec.owner.toLowerCase() : null;
  }

  // The tenant's root public key, registered by the admin. The first one stays: the same key again is fine, another
  // is refused (a new root is a new tenant). Without it no device may connect.
  async setRoot(b64: string): Promise<"ok" | "conflict" | "bad"> {
    const key = b64bytes(b64, 32);
    if (!key) return "bad";
    const canonical = btoa(String.fromCharCode(...key));
    const cur = await this.ctx.storage.get<string>("root");
    if (cur !== undefined) return cur === canonical ? "ok" : "conflict";
    await this.ctx.storage.put("root", canonical);
    return "ok";
  }

  // The registered root public key (base64), or null. Public by design: a daemon compares its fingerprint with the
  // one the admin shared out of band, so a gateway that serves a different key is caught there.
  async rootKey(): Promise<string | null> {
    return (await this.ctx.storage.get<string>("root")) ?? null;
  }

  // The device's signing key and binding version if it may connect now: not revoked, an approved enrollment whose
  // binding the registered root signed for this tenant and device and that has not expired, and whose key is the one
  // that was enrolled. Anything else is null.
  private async connectable(tenant: string, device: string): Promise<{ key: Uint8Array; version: number } | null> {
    const root = b64bytes((await this.ctx.storage.get<string>("root")) ?? "", 32);
    if (!root || !isDeviceId(device) || (await this.revokedIds()).has(device)) return null;
    const rec = await this.ctx.storage.get<StoredEnrollment>(`enr:${device}`);
    if (!rec || rec.status !== "approved" || !rec.binding) return null;
    const ok = await verifyBinding(root, rec.binding, tenant, Date.now());
    return ok && ok.device === device && btoa(String.fromCharCode(...ok.key)) === rec.signing_key ? ok : null;
  }

  // A challenge for the device. Only a device that may connect gets one stored (by hash, 60 s, a few at a time);
  // for any other the answer is the same shape and nothing is stored.
  issueChallenge(tenant: string, device: string): Promise<{ challenge: string; expires_at: number }> {
    // Serialized, so concurrent requests cannot each count the same outstanding challenges and exceed the cap.
    return this.ctx.blockConcurrencyWhile(async () => {
      const challenge = randomChallenge();
      const now = Date.now();
      const out = { challenge, expires_at: now + CHALLENGE_TTL_MS };
      if (!(await this.connectable(tenant, device))) return out;
      const mine = [...(await this.ctx.storage.list<StoredConnect>({ prefix: `chal:${device}:` }))].sort((a, b) => a[1].created - b[1].created);
      await Promise.all([
        this.ctx.storage.put(`chal:${device}:${await sha256(challenge)}`, { created: now, exp: out.expires_at } satisfies StoredConnect),
        ...this.deleteAll(mine.slice(0, Math.max(0, mine.length - MAX_CHALLENGES_PER_DEVICE + 1)).map(([k]) => k)),
      ]);
      await this.schedule(out.expires_at);
      return out;
    });
  }

  // Issues a connect token. The challenge is consumed first, so it is single use whatever else is wrong. Null, for
  // every reason alike, unless the challenge is ours, unexpired and issued for this device, the device may connect
  // at exactly `version`, and `signature` is the device's over connectMessage for that challenge, its expiry,
  // the version and the scope.
  issueConnectToken(tenant: string, device: string, challenge: string, version: number, scope: ConnectScope, signature: string): Promise<{ secret: string; expires_at: number } | null> {
    // Serialized: the consumption of a challenge must not interleave with a second redemption of it.
    return this.ctx.blockConcurrencyWhile(async () => {
      const k = `chal:${device}:${await sha256(challenge)}`;
      const rec = await this.ctx.storage.get<StoredConnect>(k);
      if (!rec) return null;
      await this.ctx.storage.delete(k);
      const now = Date.now();
      const bound = await this.connectable(tenant, device);
      const sig = b64bytes(signature, 64);
      if (rec.exp <= now || !bound || bound.version !== version || !sig) return null;
      if (!(await verifyEd25519(bound.key, sig, connectMessage(tenant, device, challenge, rec.exp, version, scope)))) return null;
      const secret = random(32);
      const mine = [...(await this.ctx.storage.list<StoredConnect>({ prefix: `dtk:${device}:` }))].sort((a, b) => a[1].created - b[1].created);
      await Promise.all([
        this.ctx.storage.put(`dtk:${device}:${await sha256(secret)}`, { created: now, exp: now + CONNECT_TOKEN_TTL_MS, version, scope } satisfies StoredConnect),
        ...this.deleteAll(mine.slice(0, Math.max(0, mine.length - MAX_CONNECT_TOKENS_PER_DEVICE + 1)).map(([k2]) => k2)),
      ]);
      await this.schedule(now + CONNECT_TOKEN_TTL_MS);
      return { secret, expires_at: now + CONNECT_TOKEN_TTL_MS };
    });
  }

  // Whether the token authenticates the device for `scope` now: known, of that scope, unexpired, and the device
  // still connectable at the binding version the token was issued for. A "connect" token is deleted by being
  // presented, before any check but its existence (the read and the delete have no other await between them).
  async connectAuth(tenant: string, device: string, secret: string, scope: ConnectScope): Promise<boolean> {
    const k = `dtk:${device}:${await sha256(secret)}`;
    const rec = await this.ctx.storage.get<StoredConnect>(k);
    if (!rec || rec.scope !== scope) return false;
    if (scope === "connect" || rec.exp <= Date.now()) await this.ctx.storage.delete(k);
    const bound = rec.exp > Date.now() ? await this.connectable(tenant, device) : null;
    if (bound?.version === rec.version) return true;
    await this.ctx.storage.delete(k);
    return false;
  }

  // Every live device and its owner. A card is only as live as its device: once
  // the enrollment is purged or the device revoked, the card stops being listed
  // or resolvable.
  private async enrolledOwners(): Promise<Map<string, string>> {
    const revoked = await this.revokedIds();
    const out = new Map<string, string>();
    for (const [k, r] of await this.ctx.storage.list<StoredEnrollment>({ prefix: "enr:" })) {
      if (r.status === "approved" && r.binding && !revoked.has(k.slice(4))) out.set(k.slice(4), r.owner.toLowerCase());
    }
    return out;
  }

  // Deletes keys in batches of 128 (the storage limit). Called without an await
  // between it and the caller's other writes, the whole set is one atomic commit.
  private deleteAll(keys: string[]): Promise<unknown>[] {
    const out: Promise<unknown>[] = [];
    for (let i = 0; i < keys.length; i += 128) out.push(this.ctx.storage.delete(keys.slice(i, i + 128)));
    return out;
  }

  // Applies a change together with its audit event. The read comes first and the
  // writes are issued with no await between them, so storage commits them as one
  // unit (no half-applied edit, no change without its event); the input gate
  // keeps other requests from interleaving with the read. Events are numbered
  // 1, 2, 3... with no gaps, so the log is capped exactly: event n evicts event
  // n - MAX_AUDIT in the same commit.
  private async commit(puts: Record<string, unknown>, dels: string[], ev: Omit<AuditEvent, "at">) {
    const seq = ((await this.ctx.storage.get<number>("auds")) ?? 0) + 1;
    const key = (n: number) => `aud:${String(n).padStart(12, "0")}`;
    await Promise.all([
      this.ctx.storage.put({ ...puts, [key(seq)]: { at: Date.now(), ...ev } satisfies AuditEvent, auds: seq }),
      ...this.deleteAll(seq > MAX_AUDIT ? [...dels, key(seq - MAX_AUDIT)] : dels),
    ]);
  }

  // The audit log, oldest first, one page at a time.
  async auditLog(page: Page): Promise<{ events: (AuditEvent & { id: string })[]; next_cursor?: string }> {
    const all = await this.ctx.storage.list<AuditEvent>({ prefix: "aud:", limit: MAX_AUDIT });
    const r = paginate([...all].map(([k, e]) => ({ id: k.slice(4), ...e })), (e) => e.id, page);
    return { events: r.items, ...(r.next_cursor ? { next_cursor: r.next_cursor } : {}) };
  }

  // Publishes (or replaces, by name) a card for the calling device. The secrets
  // lint runs here: the gateway cannot read task content, only these plaintext cards.
  async publishCard(device: string, raw: unknown): Promise<{ id: string } | { error: DirectoryError; field?: string }> {
    // The only non-storage await comes first, so nothing can interleave between
    // the checks below and the write.
    const v = validateCard(raw);
    const hash = "card" in v ? (await sha256(v.card.name.toLowerCase())).slice(0, 16) : "";
    const owner = await this.ownerOf(device);
    if (!owner) return { error: "not_enrolled" };
    if ("error" in v) return v;
    const id = `${device}:${hash}`;
    const all = await this.ctx.storage.list({ prefix: "card:", limit: MAX_CARDS_PER_TENANT });
    if (!all.has(`card:${id}`)) {
      const mine = [...all.keys()].filter((k) => k.startsWith(`card:${device}:`)).length;
      if (mine >= MAX_CARDS_PER_DEVICE || all.size >= MAX_CARDS_PER_TENANT) return { error: "too_many_cards" };
    }
    await this.commit({ [`card:${id}`]: { ...v.card, id, device_id: device, owner, published: Date.now() } satisfies DirectoryEntry }, [], {
      action: "card.publish",
      actor: device,
      subject: id,
      detail: { visibility: v.card.visibility, groups: v.card.groups.length },
    });
    return { id };
  }

  async removeCard(device: string, id: string): Promise<boolean> {
    if (!isDeviceId(device) || !isCardId(id) || !id.startsWith(`${device}:`)) return false; // only the publishing device
    if ((await this.ctx.storage.get(`card:${id}`)) === undefined) return false;
    await this.commit({}, [`card:${id}`], { action: "card.remove", actor: device, subject: id });
    return true;
  }

  private async viewerGroups(viewer: string) {
    const all = await this.ctx.storage.list<{ members: string[] }>({ prefix: "grp:", limit: MAX_GROUPS });
    return memberships([...all].map(([k, g]) => [k.slice(4), g.members]), viewer);
  }

  // find_agents: the cards the calling device's owner may see, filtered by name,
  // description and tag, one page at a time. Cards the viewer may not see are not
  // mentioned. The read is bounded by MAX_CARDS_PER_TENANT.
  async find(device: string, rawQuery: unknown, page: Page): Promise<{ agents: DirectoryEntry[]; next_cursor?: string } | { error: DirectoryError }> {
    const viewer = await this.ownerOf(device);
    if (!viewer) return { error: "not_enrolled" };
    const q = validateQuery(rawQuery);
    if (!q) return { error: "bad_query" };
    const groups = await this.viewerGroups(viewer);
    const all = await this.ctx.storage.list<DirectoryEntry>({ prefix: "card:", limit: MAX_CARDS_PER_TENANT });
    const live = await this.enrolledOwners();
    const visible = [...all.values()]
      .map((c) => ({ ...c, owner: live.get(c.device_id) ?? "" }))
      .filter((c) => c.owner && canSee(c, c.owner, viewer, groups) && matches(c, q))
      .sort((a, b) => (cardKey(a) < cardKey(b) ? -1 : 1));
    const r = paginate(visible, cardKey, page);
    return { agents: r.items, ...(r.next_cursor ? { next_cursor: r.next_cursor } : {}) };
  }

  // The card the calling device may send to, or null. Unknown, hidden and
  // not-permitted are the same answer. VISIBILITY ONLY: a card returned here is
  // not permission to call it; the target daemon checks the allowlist from the
  // signed binding and the gateway never grants what the binding does not.
  async resolve(device: string, id: string): Promise<DirectoryEntry | null> {
    const viewer = await this.ownerOf(device);
    if (!viewer || !isCardId(id)) return null;
    const c = await this.ctx.storage.get<DirectoryEntry>(`card:${id}`);
    const owner = c && (await this.ownerOf(c.device_id));
    return c && owner && canSee(c, owner, viewer, await this.viewerGroups(viewer)) ? { ...c, owner } : null;
  }

  // Groups are managed by the admin; membership is by identity (email or named
  // service owner). Names are plaintext metadata. Each edit is one atomic commit.
  async putGroup(name: unknown, members: unknown): Promise<{ name: string; members: string[] } | { error: DirectoryError }> {
    const g = validateGroup(name, members);
    if ("error" in g) return g;
    if (!(await this.ctx.storage.get(`grp:${g.name}`)) && (await this.ctx.storage.list({ prefix: "grp:", limit: MAX_GROUPS })).size >= MAX_GROUPS) {
      return { error: "too_many_groups" };
    }
    await this.commit({ [`grp:${g.name}`]: { members: g.members } }, [], { action: "group.put", actor: "admin", subject: g.name, detail: { members: g.members.length } });
    return g;
  }

  async deleteGroup(name: unknown): Promise<boolean> {
    const n = validateGroup(name, []);
    if ("error" in n || (await this.ctx.storage.get(`grp:${n.name}`)) === undefined) return false;
    await this.commit({}, [`grp:${n.name}`], { action: "group.delete", actor: "admin", subject: n.name });
    return true;
  }

  // Group names and sizes, one page at a time (members come from `group`).
  async groups(page: Page): Promise<{ groups: { name: string; member_count: number }[]; next_cursor?: string }> {
    const all = await this.ctx.storage.list<{ members: string[] }>({ prefix: "grp:", limit: MAX_GROUPS });
    const r = paginate([...all].map(([k, g]) => ({ name: k.slice(4), member_count: g.members.length })), (g) => g.name, page);
    return { groups: r.items, ...(r.next_cursor ? { next_cursor: r.next_cursor } : {}) };
  }

  // One group's members, sorted, one page at a time; null if there is no such group.
  async group(name: unknown, page: Page): Promise<{ name: string; members: string[]; next_cursor?: string } | null> {
    const n = validateGroup(name, []);
    const g = "error" in n ? undefined : await this.ctx.storage.get<{ members: string[] }>(`grp:${n.name}`);
    if (!g || "error" in n) return null;
    const r = paginate([...g.members].sort(), (m) => m, page);
    return { name: n.name, members: r.items, ...(r.next_cursor ? { next_cursor: r.next_cursor } : {}) };
  }

  async retention(): Promise<RetentionSettings> {
    return (await this.ctx.storage.get<RetentionSettings>("retention")) ?? { mode: "strict", queue_ttl_ms: QUEUE_TTL_DEFAULT_MS };
  }

  // Sets the retention mode and, optionally, the Queued TTL (15 minutes to 24
  // hours; unchanged when omitted). Applies to tasks created from now on.
  async setRetention(raw: unknown): Promise<RetentionSettings | { error: "bad_retention" }> {
    const r = typeof raw === "object" && raw !== null && !Array.isArray(raw) ? (raw as Record<string, unknown>) : null;
    if (!r || !Object.keys(r).every((k) => k === "mode" || k === "queue_ttl_ms") || (r.mode !== "strict" && r.mode !== "queued")) return { error: "bad_retention" };
    const ttl = r.queue_ttl_ms === undefined ? (await this.retention()).queue_ttl_ms : r.queue_ttl_ms;
    if (typeof ttl !== "number" || !Number.isSafeInteger(ttl) || ttl < QUEUE_TTL_MIN_MS || ttl > QUEUE_TTL_MAX_MS) return { error: "bad_retention" };
    const next: RetentionSettings = { mode: r.mode, queue_ttl_ms: ttl };
    await this.commit({ retention: next }, [], { action: "retention.put", actor: "admin", subject: next.mode, detail: { queue_ttl_ms: ttl } });
    return next;
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
    for (const [k, l] of await this.ctx.storage.list<StoredLogin>({ prefix: "lgn:" })) await due(k, l.exp);
    const live = await this.enrolledOwners();
    const orphans = [...(await this.ctx.storage.list({ prefix: "card:", limit: MAX_CARDS_PER_TENANT })).keys()].filter((k) => !live.has(k.slice(5).split(":")[0]!));
    await Promise.all(this.deleteAll(orphans));
    for (const [k, s] of await this.ctx.storage.list<Session>({ prefix: "ses:" })) await due(k, s.exp);
    for (const prefix of ["dtk:", "chal:"]) for (const [k, c] of await this.ctx.storage.list<StoredConnect>({ prefix })) await due(k, c.exp);
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
