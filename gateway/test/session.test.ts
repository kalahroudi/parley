// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { isAdmin, issueSession } from "../src/session";
import { MAX_SESSIONS_PER_USER, SESSION_TTL_MS, type Tenant } from "../src/tenant";
import type { Env } from "../src/index";

let n = 0;
const tenant = () => `ses${++n}`;
const stub = (t: string) => env.TENANT.get(env.TENANT.idFromName(t)) as DurableObjectStub<Tenant>;
const mint = async (t: string, role: "admin" | "user" = "admin", email = "admin@example.test") => {
  const s = await stub(t).createSession(email, role);
  return { ...s, token: `ps_${t}.${s.secret}` };
};
const call = (path: string, init: { cookie?: string; bearer?: string; origin?: string; csrf?: string; body?: unknown } = {}) =>
  SELF.fetch(`https://gw${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(init.cookie ? { cookie: `parley_session=${init.cookie}` } : {}),
      ...(init.bearer ? { Authorization: init.bearer } : {}),
      ...(init.origin ? { Origin: init.origin } : {}),
      ...(init.csrf ? { "X-CSRF-Token": init.csrf } : {}),
    },
    body: JSON.stringify(init.body ?? {}),
  });

describe("who gets in", () => {
  it("no session, a malformed one, an unknown one and dev bearers are all 401", async () => {
    const t = tenant();
    const { secret } = await mint(t);
    for (const init of [
      {},
      { bearer: "Bearer dev-admin:" + t },
      { bearer: `Bearer dev-user:${t}:a@example.test` },
      { bearer: "Bearer dev:t:d" },
      { bearer: "Bearer ps_nodot" },
      { bearer: `Bearer ps_${t}.${secret.slice(1)}` }, // wrong length
      { bearer: `Bearer ps_${t}.${"0".repeat(64)}` }, // unknown
      { bearer: `Bearer ps_bad tenant.${secret}` },
      { cookie: "garbage" },
    ]) {
      expect((await call("/v1/admin/enrollments", init)).status, JSON.stringify(init)).toBe(401);
    }
    // A bad Authorization header is not rescued by a valid cookie.
    expect((await call("/v1/admin/enrollments", { bearer: "Bearer nope", cookie: `ps_${t}.${secret}`, origin: "https://gw" })).status).toBe(401);
  });

  it("a session is only good for its own tenant", async () => {
    const a = await mint(tenant());
    const forged = `ps_${tenant()}.${a.secret}`;
    expect((await call("/v1/admin/enrollments", { bearer: `Bearer ${forged}` })).status).toBe(401);
  });

  it("a signed-in non-admin is refused with 403", async () => {
    const u = await mint(tenant(), "user", "bob@example.test");
    expect((await call("/v1/admin/enrollments", { bearer: `Bearer ${u.token}` })).status).toBe(403);
  });

  it("the admin allowlist is per tenant and case-insensitive", () => {
    const e = { ADMINS: " t1:Root@Example.test , t2:other@example.test" } as Env;
    expect(isAdmin(e, "t1", "root@example.test")).toBe(true);
    expect(isAdmin(e, "t2", "root@example.test")).toBe(false);
    expect(isAdmin(e, "t3", "other@example.test")).toBe(false);
    expect(isAdmin({} as Env, "t1", "root@example.test")).toBe(false);
  });
});

describe("issuing a session", () => {
  const req = (proto = "https") => new Request(`${proto}://gw/auth/google/callback`);
  const e = { ...env, ADMINS: "tx:root@example.test" } as Env;

  it("sets an HttpOnly, SameSite=Strict, Secure cookie and keeps the token out of the body", async () => {
    const r = await issueSession(req(), e, "tx", "admin", "Root@example.test".toLowerCase());
    expect(r.status).toBe(200);
    const c = r.headers.get("set-cookie")!;
    expect(c).toMatch(/^parley_session=ps_tx\.[0-9a-f]{64}; /);
    for (const a of ["Path=/", "HttpOnly", "SameSite=Strict", "Secure", `Max-Age=${SESSION_TTL_MS / 1000}`]) expect(c).toContain(a);
    const body = (await r.json()) as any;
    expect(body).toMatchObject({ role: "admin", tenant: "tx", email: "root@example.test" });
    expect(body.csrf).toMatch(/^[0-9a-f]{32}$/);
    expect(JSON.stringify(body)).not.toContain(c.split(";")[0]!.split("=")[1]!);
    expect(r.headers.get("cache-control")).toBe("no-store");
  });

  it("omits Secure over plain http (local development) only", async () => {
    const r = await issueSession(req("http"), e, "tx", "user", "bob@example.test");
    expect(r.headers.get("set-cookie")).not.toContain("Secure");
    expect(r.headers.get("set-cookie")).toContain("HttpOnly");
  });

  it("refuses an admin session to anyone not on the list, and bad tenant ids", async () => {
    expect((await issueSession(req(), e, "tx", "admin", "mallory@example.test")).status).toBe(403);
    expect((await issueSession(req(), e, "other", "admin", "root@example.test")).status).toBe(403);
    expect((await issueSession(req(), e, "bad tenant", "user", "bob@example.test")).status).toBe(400);
  });

  it("the issued cookie works, with CSRF", async () => {
    const r = await issueSession(req(), e, "tx", "admin", "root@example.test");
    const cookie = r.headers.get("set-cookie")!.split(";")[0]!.split("=")[1]!;
    const { csrf } = (await r.json()) as any;
    expect((await call("/v1/admin/enrollments", { cookie, origin: "https://gw", csrf })).status).toBe(200);
  });
});

describe("cookie sessions need CSRF protection", () => {
  it("rejects a missing token, a wrong token and a foreign or absent Origin, and changes nothing", async () => {
    const t = tenant();
    const s = await mint(t);
    const ok = { cookie: `ps_${t}.${s.secret}`, origin: "https://gw", csrf: s.csrf };
    const mintTok = (init: object) => call("/v1/admin/enrollment-tokens", { ...ok, ...init, body: { owner: "svc" } });
    const count = () => runInDurableObject(stub(t), async (_i, ctx) => (await ctx.storage.list({ prefix: "tok:" })).size);

    expect((await mintTok({ csrf: undefined })).status).toBe(403);
    expect((await mintTok({ csrf: "0".repeat(32) })).status).toBe(403);
    expect((await mintTok({ csrf: s.csrf.slice(1) })).status).toBe(403);
    expect((await mintTok({ origin: "https://evil.example" })).status).toBe(403);
    expect((await mintTok({ origin: undefined })).status).toBe(403);
    expect((await mintTok({ origin: "https://gw.evil.example" })).status).toBe(403);
    expect(await count()).toBe(0);

    expect((await mintTok({})).status).toBe(201);
    expect(await count()).toBe(1);
  });

  it("also guards user enrollment requests and sign-out", async () => {
    const t = tenant();
    const u = await mint(t, "user", "bob@example.test");
    const key = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    const body = { name: "laptop", signing_key: key };
    const base = { cookie: `ps_${t}.${u.secret}`, body };
    expect((await call("/v1/enroll/request", { ...base, origin: "https://gw" })).status).toBe(403);
    expect((await call("/v1/enroll/request", { ...base, origin: "https://gw", csrf: u.csrf })).status).toBe(202);
    expect((await call("/v1/session/logout", { cookie: base.cookie, origin: "https://evil.example", csrf: u.csrf })).status).toBe(403);
    expect((await call("/v1/session", { cookie: base.cookie })).status).toBe(200); // still signed in
  });

  it("a bearer token needs no CSRF header (it is not sent by the browser on its own)", async () => {
    const s = await mint(tenant());
    expect((await call("/v1/admin/enrollments", { bearer: `Bearer ${s.token}` })).status).toBe(200);
  });
});

describe("expiry and sign-out", () => {
  it("an expired session is refused and its record purged", async () => {
    const t = tenant();
    const s = await mint(t);
    await runInDurableObject(stub(t), async (_i, ctx) => {
      for (const [k, v] of await ctx.storage.list<any>({ prefix: "ses:" })) await ctx.storage.put(k, { ...v, exp: Date.now() - 1 });
    });
    expect((await call("/v1/session", { bearer: `Bearer ${s.token}` })).status).toBe(401);
    expect(await runInDurableObject(stub(t), async (_i, ctx) => (await ctx.storage.list({ prefix: "ses:" })).size)).toBe(0);
  });

  it("the alarm purges expired sessions and keeps live ones", async () => {
    const t = tenant();
    const old = await mint(t, "admin", "a@example.test");
    const live = await mint(t, "admin", "b@example.test");
    await runInDurableObject(stub(t), async (_i, ctx) => {
      const [k, v] = [...(await ctx.storage.list<any>({ prefix: "ses:" }))].find(([, s]) => s.email === "a@example.test")!;
      await ctx.storage.put(k, { ...v, exp: Date.now() - 1 });
    });
    expect(await runDurableObjectAlarm(stub(t))).toBe(true);
    expect(await runInDurableObject(stub(t), async (_i, ctx) => (await ctx.storage.list({ prefix: "ses:" })).size)).toBe(1);
    expect(await stub(t).getSession(old.secret)).toBeNull();
    expect(await stub(t).getSession(live.secret)).not.toBeNull();
  });

  it("sign-out ends the session on the server, so the old cookie and token are rejected", async () => {
    const t = tenant();
    const s = await mint(t);
    const cookie = `ps_${t}.${s.secret}`;
    const out = await call("/v1/session/logout", { cookie, origin: "https://gw", csrf: s.csrf });
    expect(out.status).toBe(200);
    expect(out.headers.get("set-cookie")).toMatch(/^parley_session=; .*Max-Age=0/);
    expect((await call("/v1/admin/enrollments", { cookie, origin: "https://gw", csrf: s.csrf })).status).toBe(401);
    expect((await call("/v1/session", { bearer: `Bearer ${s.token}` })).status).toBe(401);
  });

  it("sessions are only stored as a hash", async () => {
    const t = tenant();
    const s = await mint(t);
    const keys = await runInDurableObject(stub(t), async (_i, ctx) => [...(await ctx.storage.list({ prefix: "ses:" })).keys()]);
    expect(keys).toHaveLength(1);
    expect(keys[0]).not.toContain(s.secret);
  });

  it("keeps at most a few sessions per user and role, dropping the oldest", async () => {
    const t = tenant();
    const all = [];
    for (let i = 0; i < MAX_SESSIONS_PER_USER + 2; i++) all.push(await mint(t, "admin", "a@example.test"));
    const other = await mint(t, "user", "a@example.test"); // a different role is counted separately
    const alive = await Promise.all(all.map(async (s) => (await stub(t).getSession(s.secret)) !== null));
    expect(alive.filter(Boolean)).toHaveLength(MAX_SESSIONS_PER_USER);
    expect(alive.slice(0, 2)).toEqual([false, false]);
    expect(await stub(t).getSession(other.secret)).not.toBeNull();
  });
});

describe("GET-style probes and routing", () => {
  it("/v1/session reports the session; other methods and paths are refused", async () => {
    const t = tenant();
    const s = await mint(t);
    const r = (await (await call("/v1/session", { bearer: `Bearer ${s.token}` })).json()) as any;
    expect(r).toEqual({ role: "admin", tenant: t, email: "admin@example.test", csrf: s.csrf });
    expect((await SELF.fetch("https://gw/v1/session")).status).toBe(405);
    expect((await call("/v1/session")).status).toBe(401);
    expect((await call("/v1/session/nope", { bearer: `Bearer ${s.token}` })).status).toBe(404); // not routed here
  });
});

describe("login routes", () => {
  it("/auth/* is served by the OIDC handler (no provider is configured in tests)", async () => {
    expect((await SELF.fetch("https://gw/auth/google/login?tenant=t&role=admin")).status).toBe(404);
  });
});
