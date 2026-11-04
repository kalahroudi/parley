// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { isDeviceId } from "./acl";
import { readBounded, type Identity } from "./a2a";
import type { Env } from "./index";
import { limitDevice } from "./ratelimit";
import type { Tenant } from "./tenant";

// Device connect tokens. A device proves it holds the key its ROOT-SIGNED binding names, and gets a short-lived token:
//
//   POST /v1/connect/challenge {tenant, device}
//     -> {challenge, expires_at}. For a device that may connect the Tenant DO stores the hash of a random challenge
//        (single use, 60 s, at most MAX_CHALLENGES_PER_DEVICE outstanding, removed by the alarm). For any other
//        device the answer looks the same and nothing is stored, so asking costs storage only for real devices
//        and does not say whether the device exists.
//   POST /v1/connect/token {tenant, device, challenge, version, scope, signature}
//     -> {token, expires_at}. The challenge is consumed first, whatever follows. The signature is Ed25519 over
//        connectMessage (label, tenant, device, challenge, its expiry, the binding version, the scope) and is checked
//        against the key in the binding, which is itself verified against the tenant's root public key (signature
//        and not_after) every time. Revoked, expired, unbound, wrong-tenant, wrong-version and unknown devices, and
//        a replayed or expired challenge, all get the same 401.
//
// The token is `pdt_<tenant>.<device>.<secret>`, 256 bits, kept only as a hash, bound to tenant, device, binding
// version and scope. Scope "connect" opens the tunnel and is consumed by the upgrade that presents it; scope "api"
// serves /a2a until it expires. Each use re-checks that the device is still connectable
// at that binding version, so a revocation or a new binding ends tokens at once.
export const CHALLENGE_TTL_MS = 60_000;
export const CONNECT_LABEL = "parley/connect/v2";
export const BINDING_LABEL = "parley/binding/v1";
export type Scope = "connect" | "api";
const MAX_BODY_BYTES = 4096;
const TENANT_ID = /^[A-Za-z0-9_-]{1,64}$/;
// The whole Authorization header: the scheme, then pdt_<tenant>.<device>.<secret>.
const BEARER_TOKEN = /^Bearer pdt_([A-Za-z0-9_-]{1,64})\.([0-9a-f]{32})\.([0-9a-f]{64})$/;
const json = (status: number, body: unknown, headers: HeadersInit = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });

const te = new TextEncoder();
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

// Length-prefixed fields (4 bytes, big endian) and 8-byte big-endian integers: no field boundary is ambiguous.
// internal/connect (Go) and internal/binding build the same bytes.
function encode(parts: (string | Uint8Array | bigint)[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  for (const p of parts) {
    const raw = new Uint8Array(8);
    if (typeof p === "bigint") {
      new DataView(raw.buffer).setBigUint64(0, p);
      chunks.push(raw);
    } else {
      const bytes = typeof p === "string" ? te.encode(p) : p;
      new DataView(raw.buffer).setUint32(0, bytes.length);
      chunks.push(raw.subarray(0, 4), bytes);
    }
  }
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

export const connectMessage = (tenant: string, device: string, challenge: string, expires: number, version: number, scope: Scope) =>
  encode([CONNECT_LABEL, tenant, device, challenge, BigInt(expires), BigInt(version), scope]);

// The bytes of a base64 string of exactly `length` bytes, else null. Anything that is not a string is null (an array
// of one string would otherwise be read as that string).
export function b64bytes(v: unknown, length: number): Uint8Array | null {
  if (typeof v !== "string") return null;
  try {
    const bin = atob(v);
    // atob also takes whitespace, missing padding and stray trailing bits: only the one canonical spelling is accepted.
    return bin.length === length && btoa(bin) === v ? Uint8Array.from(bin, (c) => c.charCodeAt(0)) : null;
  } catch {
    return null;
  }
}

// The key is imported not extractable, for this one check. A key the runtime cannot import is a failed check, not a
// throw (a throw inside the Tenant DO's blockConcurrencyWhile would reset the whole object).
export async function verifyEd25519(key: Uint8Array, sig: Uint8Array, msg: Uint8Array): Promise<boolean> {
  try {
    return await crypto.subtle.verify({ name: "Ed25519" }, await crypto.subtle.importKey("raw", key, { name: "Ed25519" }, false, ["verify"]), sig, msg);
  } catch {
    return false;
  }
}

// A binding is good for `tenant` at `now` when every field is present and well formed, the root's signature over
// internal/binding's encoding verifies, and not_after is still ahead. Returns the device's signing key and the
// binding version, else null. The gateway holds no key of its own for this: only the root public key the admin
// registered, so a stored binding the root did not sign opens nothing. not_after must be exactly what
// internal/binding writes, a UTC time in whole seconds (`2099-01-01T00:00:00Z`): the date is parsed and written
// back, and anything that does not come back identical (another offset, fractions, other spellings) is refused.
export async function verifyBinding(root: Uint8Array, b: unknown, tenant: string, now: number): Promise<{ key: Uint8Array; version: number; device: string } | null> {
  const r = (b ?? {}) as Record<string, unknown>;
  const key = b64bytes(r.signing_key, 32);
  const sig = b64bytes(r.signature, 64);
  const ms = Date.parse(r.not_after as string);
  const exact = Number.isFinite(ms) && new Date(ms).toISOString().replace(".000Z", "Z") === r.not_after;
  if (!key || !sig || !exact || !(ms > now) || r.tenant !== tenant || typeof r.owner !== "string" || !r.owner || typeof r.device_id !== "string" || !r.device_id) return null;
  const version = r.version as number; // not an integer in 1..2^53 (including any non-number): refused
  if (!Number.isSafeInteger(version) || version < 1) return null;
  const msg = encode([BINDING_LABEL, tenant, r.owner, r.device_id, key, BigInt(version), BigInt(ms / 1000)]);
  return (await verifyEd25519(root, sig, msg)) ? { key, version, device: r.device_id } : null;
}

const tenantStub = (env: Env, tenant: string) => env.TENANT.get(env.TENANT.idFromName(tenant)) as DurableObjectStub<Tenant>;
const limited = (wait: number) => json(429, { error: "rate_limited" }, { "retry-after": String(Math.ceil(wait / 1000)) });

// POST /v1/connect/challenge and /v1/connect/token. Both count against the device's rate-limit budget (and the
// source's, in the Worker) before they touch storage; a limiter that fails refuses. A request that is not well
// formed is a 400 whose code says which part (syntax only, nothing about any device).
export async function handleConnectAuth(req: Request, env: Env): Promise<Response> {
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
  let b: unknown = null;
  try {
    // An oversized body reads as null, which parses to null.
    b = JSON.parse((await readBounded(req, MAX_BODY_BYTES)) as string);
  } catch {
    // Not JSON, or not UTF-8: b stays null.
  }
  if (b === null || typeof b !== "object") return json(400, { error: "bad_json" });
  const { tenant, device, challenge, version, scope, signature } = b as Record<string, unknown>;
  if (typeof tenant !== "string" || !TENANT_ID.test(tenant) || !isDeviceId(device)) return json(400, { error: "bad_ids" });
  const stub = tenantStub(env, tenant);

  if (new URL(req.url).pathname === "/v1/connect/challenge") {
    const wait = await limitDevice(env, tenant, device, "connect");
    return wait === null ? json(200, await stub.issueChallenge(tenant, device)) : limited(wait);
  }

  // The only other route the Worker sends here is /v1/connect/token.
  if (typeof challenge !== "string" || challenge.length > 128) return json(400, { error: "bad_challenge" });
  if (!Number.isSafeInteger(version) || (version as number) < 1) return json(400, { error: "bad_version" });
  if (scope !== "connect" && scope !== "api") return json(400, { error: "bad_scope" });
  if (!b64bytes(signature, 64)) return json(400, { error: "bad_signature" });
  const wait = await limitDevice(env, tenant, device, "connect");
  if (wait !== null) return limited(wait);
  const issued = await stub.issueConnectToken(tenant, device, challenge, version as number, scope, signature as string);
  return issued ? json(200, { token: `pdt_${tenant}.${device}.${issued.secret}`, expires_at: issued.expires_at }) : json(401, { error: "unauthorized" });
}

// The device behind `Authorization: Bearer pdt_...` for this scope, or null. The tenant and device come from the
// token, and the token's record must exist in that tenant's Durable Object, so a token never reaches another
// tenant's or another device's resources. A "connect" token is consumed by being presented.
export async function authenticate(req: Request, env: Env, scope: Scope): Promise<Identity | null> {
  // A missing header is null, which the pattern reads as the text "null" and does not match.
  const m = BEARER_TOKEN.exec(req.headers.get("Authorization") as string);
  if (!m) return null;
  const [, tenant, device, secret] = m;
  return (await tenantStub(env, tenant!).connectAuth(tenant!, device!, secret!, scope)) ? { tenant: tenant!, device: device! } : null;
}

export const randomChallenge = () => hex(crypto.getRandomValues(new Uint8Array(32)));
