// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { REQUEST_TTL_MS, MAX_PENDING, MAX_PENDING_PER_OWNER } from "../src/tenant";

const key = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const post = (path: string, body: unknown, auth?: string) =>
  SELF.fetch(`https://gw${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(auth ? { Authorization: auth } : {}) },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

let n = 0;
const fresh = () => {
  const t = `ten${++n}`;
  return { t, admin: `Bearer dev-admin:${t}`, user: (e = "alice@example.test") => `Bearer dev-user:${t}:${e}` };
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
    expect((await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.admin)).status).toBe(401);
    for (const body of [{ name: "d", signing_key: "AAAA" }, { name: "d", signing_key: "%%%" }, { name: "", signing_key: key() }, { name: "x".repeat(101), signing_key: key() }]) {
      expect((await post("/v1/enroll/request", body, x.user())).status).toBe(400);
    }
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
  });

  it("caps pending requests per owner so one user cannot fill the queue", async () => {
    const x = fresh();
    for (let i = 0; i < MAX_PENDING_PER_OWNER; i++) expect((await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.user())).status).toBe(202);
    expect((await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.user())).status).toBe(429);
    expect((await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.user("bob@example.test"))).status).toBe(202);
  });

  it("drops requests that outlive their TTL", async () => {
    const x = fresh();
    const { id, poll } = await json(await post("/v1/enroll/request", { name: "d", signing_key: key() }, x.user()));
    const { vi } = await import("vitest");
    vi.useFakeTimers({ now: Date.now() + REQUEST_TTL_MS + 1000, toFake: ["Date"] });
    try {
      expect((await post("/v1/admin/enrollments/decide", { id, decision: "approved" }, x.admin)).status).toBe(404);
      expect((await post("/v1/enroll/status", { tenant: x.t, id, poll })).status).toBe(404);
      expect((await json(await post("/v1/admin/enrollments", {}, x.admin))).pending).toHaveLength(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("admin-minted pod tokens", () => {
  const mint = async (x: ReturnType<typeof fresh>, body: object = { owner: "svc-ci" }) => json(await post("/v1/admin/enrollment-tokens", body, x.admin));

  it("is admin only", async () => {
    const x = fresh();
    expect((await post("/v1/admin/enrollment-tokens", { owner: "svc" })).status).toBe(401);
    expect((await post("/v1/admin/enrollment-tokens", { owner: "svc" }, x.user())).status).toBe(401);
    expect((await post("/v1/admin/enrollments", {}, x.user())).status).toBe(401);
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
  it("rejects non-POST, bad JSON and unknown admin paths; fails closed without dev auth", async () => {
    const x = fresh();
    expect((await SELF.fetch("https://gw/v1/admin/enrollments", { headers: { Authorization: x.admin } })).status).toBe(405);
    expect((await post("/v1/admin/enrollments", "{", x.admin)).status).toBe(400);
    expect((await post("/v1/admin/enrollments", "[]", x.admin)).status).toBe(400);
    expect((await post("/v1/admin/nope", {}, x.admin)).status).toBe(404);
    const { default: worker } = await import("../src/index");
    const req = new Request("https://gw/v1/admin/enrollments", { method: "POST", body: "{}", headers: { Authorization: x.admin } });
    expect((await worker.fetch(req, { ...env, DEV_AUTH: undefined })).status).toBe(401);
  });
});
