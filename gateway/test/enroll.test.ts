// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { REQUEST_TTL_MS, MAX_PENDING, MAX_PENDING_PER_OWNER, DECIDED_RETENTION_MS } from "../src/tenant";

const key = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const post = async (path: string, body: unknown, auth?: string | Promise<string>) =>
  SELF.fetch(`https://gw${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(auth ? { Authorization: await auth } : {}) },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

// A session as the OIDC callback would issue it, minted straight in the tenant's
// Durable Object (there is no HTTP route that does this without a verified login).
const session = async (t: string, role: "admin" | "user", email: string) => {
  const s = await env.TENANT.get(env.TENANT.idFromName(t)).createSession(email, role);
  return `Bearer ps_${t}.${s.secret}`;
};

let n = 0;
const fresh = () => {
  const t = `ten${++n}`;
  return { t, admin: session(t, "admin", "admin@example.test"), user: (e = "alice@example.test") => session(t, "user", e) };
};
const json = async (r: Response) => (await r.json()) as any;

describe("interactive enrollment and the approval queue", () => {
  it("queues a request, shows it to the admin, and reports the decision to the device", async () => {
    const x = fresh();
    const sk = key();
    const r = await post("/v1/enroll/request", { name: "laptop", signing_key: sk }, x.user());
    expect(r.status).toBe(202);
    const { id, poll } = await json(r);

    const list = await json(await post("/v1/admin/enrollments", {}, x.admin));
    expect(list.pending).toHaveLength(1);
    expect(list.pending[0]).toMatchObject({ id, owner: "alice@example.test", kind: "user", name: "laptop", signing_key: sk, status: "pending" });
    expect(list.pending[0].fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(list)).not.toContain(poll);
    expect(JSON.stringify(list)).not.toContain("poll_hash");

    expect(await json(await post("/v1/enroll/status", { tenant: x.t, id, poll }))).toMatchObject({ status: "pending" });
    const d = await post("/v1/admin/enrollments/decide", { id, decision: "approved" }, x.admin);
    expect(d.status).toBe(200);
    expect(await json(await post("/v1/enroll/status", { tenant: x.t, id, poll }))).toMatchObject({ status: "approved" });
    expect((await json(await post("/v1/admin/enrollments", {}, x.admin))).pending).toHaveLength(0);
  });

  it("rejection is reported, and a decision cannot be flipped", async () => {
    const x = fresh();
    const { id, poll } = await json(await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.user()));
    expect((await post("/v1/admin/enrollments/decide", { id, decision: "rejected" }, x.admin)).status).toBe(200);
    expect((await post("/v1/admin/enrollments/decide", { id, decision: "rejected" }, x.admin)).status).toBe(200);
    expect((await post("/v1/admin/enrollments/decide", { id, decision: "approved" }, x.admin)).status).toBe(409);
    expect(await json(await post("/v1/enroll/status", { tenant: x.t, id, poll }))).toMatchObject({ status: "rejected" });
  });

  it("status needs the poll secret; unknown ids are 404", async () => {
    const x = fresh();
    const { id } = await json(await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.user()));
    expect((await post("/v1/enroll/status", { tenant: x.t, id, poll: "nope" })).status).toBe(404);
    expect((await post("/v1/enroll/status", { tenant: x.t, id: "zz", poll: "nope" })).status).toBe(404);
    expect((await post("/v1/enroll/status", { id, poll: "x" })).status).toBe(400);
    expect((await post("/v1/admin/enrollments/decide", { id: "zz", decision: "approved" }, x.admin)).status).toBe(404);
    expect((await post("/v1/admin/enrollments/decide", { id, decision: "maybe" }, x.admin)).status).toBe(400);
  });

  it("requires a signed-in user and a valid key and name", async () => {
    const x = fresh();
    expect((await post("/v1/enroll/request", { name: "d", signing_key: key() })).status).toBe(401);
    expect((await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.admin)).status).toBe(403);
    for (const body of [{ name: "d", signing_key: "AAAA" }, { name: "d", signing_key: "%%%" }, { name: "", signing_key: key() }, { name: "x".repeat(101), signing_key: key() }]) {
      expect((await post("/v1/enroll/request", body, x.user())).status).toBe(400);
    }
  });

  it("stores the signing key in canonical base64", async () => {
    const x = fresh();
    const sk = key();
    await post("/v1/enroll/request", { name: "d", signing_key: ` ${sk.slice(0, 20)}\n${sk.slice(20)} ` }, x.user());
    expect((await json(await post("/v1/admin/enrollments", {}, x.admin))).pending[0].signing_key).toBe(sk);
  });

  it("keeps tenants apart", async () => {
    const a = fresh();
    const b = fresh();
    const { id, poll } = await json(await post("/v1/enroll/request", { name: "d", signing_key: key() }, a.user()));
    expect((await json(await post("/v1/admin/enrollments", {}, b.admin))).pending).toHaveLength(0);
    expect((await post("/v1/admin/enrollments/decide", { id, decision: "approved" }, b.admin)).status).toBe(404);
    expect((await post("/v1/enroll/status", { tenant: b.t, id, poll })).status).toBe(404);
  });

  it("caps the pending queue", async () => {
    const x = fresh();
    const stub = env.TENANT.get(env.TENANT.idFromName(x.t));
    for (let i = 0; i < MAX_PENDING; i++) await stub.request({ user: `u${i}@example.test`, name: "d", signing_key: key() });
    const r = await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.user());
    expect(r.status).toBe(429);
  }, 60_000); // MAX_PENDING sequential storage writes; slow disks (Windows CI) need far more than the 5s default

  it("drops requests that outlive their TTL", async () => {
    const x = fresh();
    const { id, poll } = await json(await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.user()));
    const { vi } = await import("vitest");
    vi.useFakeTimers({ now: Date.now() + REQUEST_TTL_MS + 1000, toFake: ["Date"] });
    try {
      const admin = session(x.t, "admin", "admin@example.test"); // the earlier session has expired by now
      expect((await post("/v1/admin/enrollments/decide", { id, decision: "approved" }, admin)).status).toBe(404);
      expect((await post("/v1/enroll/status", { tenant: x.t, id, poll })).status).toBe(404);
      expect((await json(await post("/v1/admin/enrollments", {}, admin))).pending).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("limits, validation and retention", () => {
  const storageKeys = (t: string) =>
    runInDurableObject(env.TENANT.get(env.TENANT.idFromName(t)), async (_i, state) => [...(await state.storage.list()).keys()]);
  const withTime = async (ms: number, f: () => Promise<void>) => {
    const { vi } = await import("vitest");
    vi.useFakeTimers({ now: Date.now() + ms, toFake: ["Date"] });
    try {
      await f();
    } finally {
      vi.useRealTimers();
    }
  };

  it("caps pending requests per owner without blocking other users", async () => {
    const x = fresh();
    for (let i = 0; i < MAX_PENDING_PER_OWNER; i++) expect((await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.user())).status).toBe(202);
    const over = await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.user("Alice@Example.test"));
    expect(over.status).toBe(429);
    expect(await json(over)).toEqual({ error: "owner_full" });
    expect((await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.user("bob@example.test"))).status).toBe(202);
  });

  it("rejects control, bidi and format characters in names and owners", async () => {
    const x = fresh();
    const bad = ["a\nb", "a\tb", "a\u202Eb", "a\u200Bb", "a\u2028b", "a\u00A0b", "a\u0000b", "a\uE000b", "a\uD800b", "   "];
    for (const name of bad) expect((await post("/v1/enroll/request", { name, signing_key: key() }, x.user())).status, JSON.stringify(name)).toBe(400);
    // identity headers cannot carry these characters, so go to the Tenant directly
    const stub = env.TENANT.get(env.TENANT.idFromName(x.t));
    for (const user of ["a\u202E@example.test", "a\u200B@example.test", "a\n@example.test", ""]) {
      expect(await stub.request({ user, name: "d", signing_key: key() })).toEqual({ error: "bad_request" });
    }
    for (const owner of ["svc\u202Eci", "svc\nci", "x".repeat(255)]) expect((await post("/v1/admin/enrollment-tokens", { owner }, x.admin)).status).toBe(400);
    expect((await post("/v1/enroll/request", { name: "  my laptop  ", signing_key: key() }, x.user("Alice@Example.test"))).status).toBe(202);
    const e = (await json(await post("/v1/admin/enrollments", {}, x.admin))).pending[0];
    expect(e).toMatchObject({ name: "my laptop", owner: "alice@example.test" });
  });

  it("purges used and expired tokens, and decided records after retention", async () => {
    const x = fresh();
    const used = (await json(await post("/v1/admin/enrollment-tokens", { owner: "svc" }, x.admin))).token;
    await json(await post("/v1/admin/enrollment-tokens", { owner: "svc2" }, x.admin)); // never used
    const { id: podId } = await json(await post("/v1/enroll/request", { tenant: x.t, token: used, name: "p", signing_key: key() }));
    // the used token is gone immediately; the unused one stays until it expires
    expect((await storageKeys(x.t)).filter((k) => k.startsWith("tok:"))).toHaveLength(1);
    const { id, poll } = await json(await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.user()));
    await post("/v1/admin/enrollments/decide", { id, decision: "approved" }, x.admin);

    await withTime(25 * 3600_000, async () => {
      await runDurableObjectAlarm(env.TENANT.get(env.TENANT.idFromName(x.t)));
      expect((await storageKeys(x.t)).filter((k) => k.startsWith("tok:"))).toHaveLength(0);
      expect((await post("/v1/enroll/status", { tenant: x.t, id, poll })).status).toBe(200);
    });
    await withTime(REQUEST_TTL_MS + 1000, async () => {
      await runDurableObjectAlarm(env.TENANT.get(env.TENANT.idFromName(x.t)));
      expect(await storageKeys(x.t)).toEqual([`enr:${id}`]); // the stale pending pod request is gone, the decided one is kept
      expect((await post("/v1/enroll/status", { tenant: x.t, id: podId, poll: "x" })).status).toBe(404);
    });
    await withTime(DECIDED_RETENTION_MS + 1000, async () => {
      await runDurableObjectAlarm(env.TENANT.get(env.TENANT.idFromName(x.t)));
      expect(await storageKeys(x.t)).toEqual([]);
      expect((await post("/v1/enroll/status", { tenant: x.t, id, poll })).status).toBe(404);
    });
  });
});

describe("admin-minted pod tokens", () => {
  const mint = async (x: ReturnType<typeof fresh>, body: object = { owner: "svc-ci" }) => json(await post("/v1/admin/enrollment-tokens", body, x.admin));

  it("is admin only", async () => {
    const x = fresh();
    expect((await post("/v1/admin/enrollment-tokens", { owner: "svc" })).status).toBe(401);
    expect((await post("/v1/admin/enrollment-tokens", { owner: "svc" }, x.user())).status).toBe(403);
    expect((await post("/v1/admin/enrollments", {}, x.user())).status).toBe(403);
    expect((await post("/v1/admin/enrollment-tokens", { owner: "" }, x.admin)).status).toBe(400);
  });

  it("enrolls a headless device under the named owner, once", async () => {
    const x = fresh();
    const { token } = await mint(x);
    expect(token).toMatch(/^pet_[0-9a-f]{48}$/);
    const r = await post("/v1/enroll/request", { tenant: x.t, token, name: "ci-1", signing_key: key() });
    expect(r.status).toBe(202);
    const list = await json(await post("/v1/admin/enrollments", {}, x.admin));
    expect(list.pending[0]).toMatchObject({ owner: "svc-ci", kind: "pod", name: "ci-1" });
    const again = await post("/v1/enroll/request", { tenant: x.t, token, name: "ci-2", signing_key: key() });
    expect(again.status).toBe(401);
    expect((await json(await post("/v1/admin/enrollments", {}, x.admin))).pending).toHaveLength(1);
  });

  it("concurrent use of one token admits exactly one request", async () => {
    const x = fresh();
    const { token } = await mint(x);
    const rs = await Promise.all(Array.from({ length: 8 }, () => post("/v1/enroll/request", { tenant: x.t, token, name: "p", signing_key: key() })));
    expect(rs.filter((r) => r.status === 202)).toHaveLength(1);
    expect(rs.filter((r) => r.status === 401)).toHaveLength(7);
  });

  it("a token is bound to its tenant and rejects unknown or expired values", async () => {
    const a = fresh();
    const b = fresh();
    const { token } = await mint(a);
    expect((await post("/v1/enroll/request", { tenant: b.t, token, name: "p", signing_key: key() })).status).toBe(401);
    expect((await post("/v1/enroll/request", { tenant: a.t, token: "pet_bogus", name: "p", signing_key: key() })).status).toBe(401);
    expect((await post("/v1/enroll/request", { tenant: "bad/id", token, name: "p", signing_key: key() })).status).toBe(400);
    const { vi } = await import("vitest");
    vi.useFakeTimers({ now: Date.now() + 25 * 3600_000, toFake: ["Date"] });
    try {
      expect((await post("/v1/enroll/request", { tenant: a.t, token, name: "p", signing_key: key() })).status).toBe(401);
    } finally {
      vi.useRealTimers();
    }
  });

  it("caps the ttl and does not keep the plaintext token", async () => {
    const x = fresh();
    const t = await mint(x, { owner: "svc", ttl_s: 10 * 24 * 3600 });
    expect(t.expires_at - Date.now()).toBeLessThanOrEqual(7 * 24 * 3600_000);
    const { runInDurableObject } = await import("cloudflare:test");
    const stub = env.TENANT.get(env.TENANT.idFromName(x.t));
    const keys = await runInDurableObject(stub, async (_i, state) => JSON.stringify([...(await state.storage.list()).entries()]));
    expect(keys).not.toContain(t.token);
    expect((await post("/v1/admin/enrollment-tokens", { owner: "svc", ttl_s: -5 }, x.admin)).status).toBe(400);
  });

  it("a rejected pod request still burns the token", async () => {
    const x = fresh();
    const { token } = await mint(x);
    const { id } = await json(await post("/v1/enroll/request", { tenant: x.t, token, name: "p", signing_key: key() }));
    await post("/v1/admin/enrollments/decide", { id, decision: "rejected" }, x.admin);
    expect((await post("/v1/enroll/request", { tenant: x.t, token, name: "p", signing_key: key() })).status).toBe(401);
  });
});

describe("routing", () => {
  it("rejects non-POST, bad JSON and unknown admin paths", async () => {
    const x = fresh();
    expect((await SELF.fetch("https://gw/v1/admin/enrollments", { headers: { Authorization: await x.admin } })).status).toBe(405);
    expect((await post("/v1/admin/enrollments", "{", x.admin)).status).toBe(400);
    expect((await post("/v1/admin/enrollments", "[]", x.admin)).status).toBe(400);
    expect((await post("/v1/admin/nope", {}, x.admin)).status).toBe(404);
  });
});

describe("root-signed bindings and the revocation list (relayed, never trusted)", () => {
  const b64 = (n: number) => btoa(String.fromCharCode(...new Uint8Array(n).fill(7)));
  let curId = "";
  const binding = (sk: string, version = 1, extra: object = {}) => ({ tenant: "t", owner: "a", device_id: curId, signing_key: sk, version, signature: b64(64), ...extra });
  const approved = async (x: ReturnType<typeof fresh>) => {
    const sk = key();
    const { id, poll } = await json(await post("/v1/enroll/request", { name: "d", signing_key: sk }, x.user()));
    curId = id;
    return { id, poll, sk };
  };
  const status = async (x: ReturnType<typeof fresh>, e: { id: string; poll: string }) => json(await post("/v1/enroll/status", { tenant: x.t, id: e.id, poll: e.poll }));

  it("hands the signed binding to the device once the admin approved and posted it", async () => {
    const x = fresh();
    const e = await approved(x);
    expect((await status(x, e)).binding).toBeUndefined();
    expect((await post("/v1/admin/bindings", { id: e.id, binding: binding(e.sk) }, x.admin)).status).toBe(409); // still pending
    await post("/v1/admin/enrollments/decide", { id: e.id, decision: "approved" }, x.admin);
    const bnd = binding(e.sk, 1, { owner: "alice@example.test" });
    expect((await post("/v1/admin/bindings", { id: e.id, binding: bnd }, x.admin)).status).toBe(200);
    expect(await status(x, e)).toMatchObject({ status: "approved", binding: bnd });
    // The identical binding again is fine; a higher version replaces it.
    expect((await post("/v1/admin/bindings", { id: e.id, binding: bnd }, x.admin)).status).toBe(200);
    expect((await post("/v1/admin/bindings", { id: e.id, binding: binding(e.sk, 2) }, x.admin)).status).toBe(200);
    expect((await status(x, e)).binding.version).toBe(2);
  });

  it("refuses a lower or conflicting version, another key, another device and bad input", async () => {
    const x = fresh();
    const e = await approved(x);
    await post("/v1/admin/enrollments/decide", { id: e.id, decision: "approved" }, x.admin);
    // The device id is the request id, even for the first binding.
    expect((await post("/v1/admin/bindings", { id: e.id, binding: binding(e.sk, 1, { device_id: "other" }) }, x.admin)).status).toBe(409);
    expect((await post("/v1/admin/bindings", { id: e.id, binding: binding(e.sk, 2) }, x.admin)).status).toBe(200);
    // A body far larger than any legitimate one is refused before it is parsed.
    expect((await post("/v1/admin/bindings", JSON.stringify({ id: e.id, pad: "x".repeat(200000) }), x.admin)).status).toBe(400);
    const code = async (body: unknown, auth = x.admin) => (await post("/v1/admin/bindings", body, auth)).status;
    expect(await code({ id: e.id, binding: binding(e.sk, 1) })).toBe(409);
    expect(await code({ id: e.id, binding: binding(e.sk, 2, { owner: "other" }) })).toBe(409);
    expect(await code({ id: e.id, binding: binding(key(), 3) })).toBe(409);
    expect(await code({ id: e.id, binding: binding(e.sk, 3, { device_id: "dev2" }) })).toBe(409);
    expect(await code({ id: "zz", binding: binding(e.sk) })).toBe(404);
    for (const bad of [null, [], "x", { ...binding(e.sk), version: 0 }, { ...binding(e.sk), version: 1.5 }, { ...binding(e.sk), device_id: 5 }, { ...binding(e.sk), pad: "x".repeat(5000) }]) {
      expect(await code({ id: e.id, binding: bad })).toBe(400);
    }
    expect(await code({ id: e.id, binding: binding(e.sk, 3) }, x.user())).toBe(403);
    // A binding is not posted for another tenant's enrollment.
    expect(await code({ id: e.id, binding: binding(e.sk, 3) }, fresh().admin)).toBe(404);
  });

  it("makes a request idempotent when the device chose its id and poll secret", async () => {
    const x = fresh();
    const id = "a".repeat(32);
    const poll = "b".repeat(48);
    const sk = key();
    const req = (extra: object = {}, auth: Promise<string> | string = x.user()) => post("/v1/enroll/request", { name: "laptop", signing_key: sk, id, poll, ...extra }, auth);
    const first = await req();
    expect(first.status).toBe(202);
    expect(await json(first)).toEqual({ id, poll });
    // The reply was lost: the same request again is the same request, not a second one in the queue.
    expect(await json(await req())).toEqual({ id, poll });
    expect((await json(await post("/v1/admin/enrollments", {}, x.admin))).pending).toHaveLength(1);
    expect((await json(await post("/v1/enroll/status", { tenant: x.t, id, poll }))).status).toBe("pending");
    // Another key, or another poll secret, under a taken id is a conflict and changes nothing.
    expect((await req({ signing_key: key() })).status).toBe(409);
    expect((await req({ poll: "c".repeat(48) })).status).toBe(409);
    // Malformed choices are refused, and an id needs its poll secret.
    for (const bad of [{ id: "short" }, { poll: "short" }, { id: undefined }, { poll: undefined }, { id: "A".repeat(32) }]) {
      expect((await req(bad)).status).toBe(400);
    }
    // A pod token is spent by the first request; the retry still succeeds because the request already exists.
    const mint = await json(await post("/v1/admin/enrollment-tokens", { owner: "svc" }, x.admin));
    const podId = "d".repeat(32);
    const podPoll = "e".repeat(48);
    const pod = () => post("/v1/enroll/request", { tenant: x.t, token: mint.token, name: "pod", signing_key: sk, id: podId, poll: podPoll });
    expect((await pod()).status).toBe(202);
    expect((await pod()).status).toBe(202);
    expect((await post("/v1/enroll/request", { tenant: x.t, token: mint.token, name: "pod", signing_key: key(), id: "f".repeat(32), poll: podPoll })).status).toBe(401); // spent
  });

  it("serves the registered root public key without an identity, and only for a tenant that has one", async () => {
    const x = fresh();
    expect((await post("/v1/root", { tenant: x.t })).status).toBe(404);
    const rk = key();
    expect((await post("/v1/admin/root", { root_public_key: rk }, x.admin)).status).toBe(200);
    expect(await json(await post("/v1/root", { tenant: x.t }))).toEqual({ root_public_key: rk });
    expect((await post("/v1/root", { tenant: fresh().t })).status).toBe(404); // another tenant has none
    for (const bad of [{}, { tenant: "a/b" }, { tenant: 5 }]) expect((await post("/v1/root", bad)).status).toBe(400);
  });

  it("stores the newest signed revocation list and serves it without an identity", async () => {
    const x = fresh();
    const l = (version: number, extra: object = {}) => ({ tenant: x.t, version, issued_at: "2026-01-01T00:00:00Z", revoked: [], signature: b64(64), ...extra });
    expect((await post("/v1/revocations", { tenant: x.t })).status).toBe(404);
    expect((await post("/v1/admin/revocations", { list: l(1) }, x.admin)).status).toBe(200);
    expect(await json(await post("/v1/revocations", { tenant: x.t }))).toEqual(l(1));
    expect((await post("/v1/admin/revocations", { list: l(1) }, x.admin)).status).toBe(200); // identical
    expect((await post("/v1/admin/revocations", { list: l(2, { revoked: ["d1"] }) }, x.admin)).status).toBe(200);
    expect((await json(await post("/v1/revocations", { tenant: x.t }))).revoked).toEqual(["d1"]);
    expect((await post("/v1/admin/revocations", { list: l(1) }, x.admin)).status).toBe(409); // lower
    expect((await post("/v1/admin/revocations", { list: l(2, { revoked: [] }) }, x.admin)).status).toBe(409); // different, same version
    expect((await post("/v1/admin/revocations", { list: l(3, { tenant: "other" }) }, x.admin)).status).toBe(400); // not this tenant's
    // A list with hundreds of revoked devices is larger than a binding may be, and must still be accepted.
    const many = Array.from({ length: 500 }, (_, i) => `device-${String(i).padStart(24, "0")}`);
    expect((await post("/v1/admin/revocations", { list: l(3, { revoked: many }) }, x.admin)).status).toBe(200);
    expect((await json(await post("/v1/revocations", { tenant: x.t }))).revoked).toHaveLength(500);
    for (const bad of [null, [], { ...l(4), version: 0 }, { ...l(4), pad: "x".repeat(70000) }]) {
      expect((await post("/v1/admin/revocations", { list: bad }, x.admin)).status).toBe(400);
    }
    expect((await post("/v1/admin/revocations", { list: l(4) }, x.user())).status).toBe(403);
    expect((await post("/v1/revocations", { tenant: "bad tenant!" })).status).toBe(400);
    expect((await post("/v1/revocations", { tenant: fresh().t })).status).toBe(404); // tenants are separate
  });
});
