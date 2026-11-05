// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { handleA2A, SEALED_MEDIA_TYPE } from "../src/a2a";
import { handleDirectory, type DeviceAuth } from "../src/directory";
import type { Env } from "../src/index";
import { advance, limitDevice, limitFor, reArm, TARGET_FACTOR, TENANT_FACTOR } from "../src/ratelimit";
import { b64, encodeWire, gw, header, taskBytes, taskHex } from "./wire";

describe("rate limits", () => {
  const limited = (init: Record<string, string> = {}) => ({ ...env, ...init }) as Env;
  const get = async (e: Env, path: string, ip = "198.51.100.1", method = "POST") => {
    const { default: worker } = await import("../src/index");
    return worker.fetch(new Request(`https://gw${path}`, { method, headers: { "CF-Connecting-IP": ip } }), e);
  };

  it("session endpoints refuse past the limit with 429 and Retry-After, per source", async () => {
    const e = limited({ RATE_SESSION_PER_MIN: "3" });
    for (let i = 0; i < 3; i++) expect((await get(e, "/v1/session")).status).toBe(401);
    const r = await get(e, "/v1/session");
    expect(r.status).toBe(429);
    expect(await r.json()).toEqual({ error: "rate_limited" });
    expect(Number(r.headers.get("retry-after"))).toBeGreaterThan(0);
    expect((await get(e, "/v1/session/logout")).status).toBe(429); // same source, same budget
    expect((await get(e, "/v1/session", "198.51.100.2")).status).toBe(401); // another source is not affected
  });

  it("the connect challenge and token endpoints have their own per-source budget", async () => {
    const e = limited({ RATE_CONNECT_PER_MIN: "2", RATE_SESSION_PER_MIN: "100" });
    expect((await get(e, "/v1/connect/challenge", "198.51.100.7")).status).toBe(400);
    expect((await get(e, "/v1/connect/token", "198.51.100.7")).status).toBe(400);
    expect((await get(e, "/v1/connect/challenge", "198.51.100.7")).status).toBe(429);
    expect((await get(e, "/v1/session", "198.51.100.7")).status).toBe(401); // the session budget is separate
    expect((await get(e, "/v1/connect/token", "198.51.100.8")).status).toBe(400); // so is another source's
  });

  it("login and callback share a per-source budget", async () => {
    const e = limited({ RATE_AUTH_PER_MIN: "2" });
    expect((await get(e, "/auth/google/login", "198.51.100.3", "GET")).status).toBe(404);
    expect((await get(e, "/auth/google/callback", "198.51.100.3", "GET")).status).toBe(404);
    expect((await get(e, "/auth/google/login", "198.51.100.3", "GET")).status).toBe(429);
  });

  it("a tenant's logins are limited across sources", async () => {
    const e = limited({ RATE_TENANT_LOGIN_PER_MIN: "2" });
    const q = "/auth/google/login?tenant=acme&role=user";
    expect((await get(e, q, "198.51.100.4", "GET")).status).not.toBe(429);
    expect((await get(e, q, "198.51.100.5", "GET")).status).not.toBe(429);
    expect((await get(e, q, "198.51.100.6", "GET")).status).toBe(429);
    expect((await get(e, "/auth/google/login?tenant=other&role=user", "198.51.100.6", "GET")).status).not.toBe(429);
  });

  it("fails closed when the limiter is unavailable", async () => {
    const broken = { ...env, RATE: { get: () => { throw new Error("down"); }, idFromName: () => ({}) } } as unknown as Env;
    expect((await get(broken, "/v1/session")).status).toBe(429);
  });

  it("the counter resets after its window, a refusal does not extend it, and storage stays one row that the alarm deletes", async () => {
    const id = env.RATE.idFromName("unit");
    const rl = env.RATE.get(id);
    expect((await rl.hit(2, 1500)).ok).toBe(true);
    expect((await rl.hit(2, 1500)).ok).toBe(true);
    for (let i = 0; i < 20; i++) expect((await rl.hit(2, 1500)).ok).toBe(false);
    const rows = () => runInDurableObject(rl, async (_i, ctx) => (await ctx.storage.list()).size);
    expect(await rows()).toBe(1);
    await new Promise((r) => setTimeout(r, 1600));
    // The new window is long: on a loaded CI machine (Windows) the steps below can take over a second, and a window of
    // 1.5 s would end before the alarm is run "early".
    expect((await rl.hit(2, 5000)).ok).toBe(true); // a new window, though refusals kept coming before it ended
    await runDurableObjectAlarm(rl); // early: the window is still open, so the counter stays
    expect(await rows()).toBe(1);
    expect((await rl.hit(2, 5000)).ok).toBe(true);
    expect((await rl.hit(2, 5000)).ok).toBe(false);
    await new Promise((r) => setTimeout(r, 5100));
    await runDurableObjectAlarm(rl); // (it may already have fired by itself)
    expect(await rows()).toBe(0);
  });
});

// The per-device and per-tenant budgets of the same RateLimit DO (the test environment raises the defaults so other
// suites are not limited; these tests lower them per call).
describe("device and tenant budgets", () => {
  let n = 0;
  const T = () => `rl${++n}`;
  const small = (over: Record<string, string> = {}) => ({ ...env, RATE_TASK_PER_MIN: "3", RATE_MESSAGE_PER_MIN: "3", RATE_FIND_PER_MIN: "3", RATE_PREKEY_PER_MIN: "3", ...over }) as Env;
  const lim = (e: Env, t: string, d: string, scope: "task" | "message" | "find" | "prekey" = "task", target?: string) => limitDevice(e, t, d, scope, target);

  it("allows the budget, then refuses with a wait of at most one window, per device and per scope", async () => {
    const e = small();
    const t = T();
    for (let i = 0; i < 3; i++) expect(await lim(e, t, "alice")).toBeNull();
    const w = await lim(e, t, "alice");
    expect(w).toBeGreaterThan(0);
    expect(w).toBeLessThanOrEqual(60_000);
    expect(w! % 1000).toBe(0);
    expect(await lim(e, t, "bob")).toBeNull(); // another device
    expect(await lim(e, t, "alice", "message")).toBeNull(); // another scope
    expect(await lim(e, t, "alice", "find")).toBeNull();
    // Prekey frames have a budget of their own, in their own bucket.
    for (let i = 0; i < 3; i++) expect(await lim(e, t, "alice", "prekey")).toBeNull();
    expect(await lim(e, t, "alice", "prekey")).toBeGreaterThan(0);
    expect(await lim(e, t, "alice")).toBeGreaterThan(0); // the task scope was spent above, and is a different one
    expect(await lim(e, t, "carol", "prekey")).toBeNull();
  });

  it("a target's budget is TARGET_FACTOR times the caller's, spent after the caller's, per tenant", async () => {
    const e = small();
    const t = T();
    for (let i = 0; i < 3 * TARGET_FACTOR; i++) expect(await lim(e, t, `c${i}`, "prekey", "bob")).toBeNull();
    expect(await lim(e, t, "late", "prekey", "bob")).toBeGreaterThan(0); // the target's is spent; the caller's is not
    expect(await lim(e, t, "late", "prekey", "dave")).toBeNull(); // so the caller is free for another target
    expect(await lim(e, T(), "late", "prekey", "bob")).toBeNull(); // another tenant's bob is another budget
    // Being a target is not being a caller: a device's own budget as a caller is separate from the one it has as a target.
    const t3 = T();
    for (let i = 0; i < 3; i++) expect(await lim(e, t3, "x", "prekey", "y")).toBeNull();
    expect(await lim(e, t3, "x", "prekey", "y")).toBeGreaterThan(0);
    for (let i = 0; i < 3 * TARGET_FACTOR; i++) expect(await lim(e, t3, `c${i}`, "prekey", "x")).toBeNull();
    // A refused caller does not spend the target's budget: a flood by one is stopped by its own.
    const t2 = T();
    for (let i = 0; i < 10; i++) await lim(e, t2, "flood", "prekey", "bob");
    for (let i = 0; i < 3 * TARGET_FACTOR - 3; i++) expect(await lim(e, t2, `o${i}`, "prekey", "bob")).toBeNull();
    expect(await lim(e, t2, "z", "prekey", "bob")).toBeGreaterThan(0);
  });

  it("budgets never cross tenants, even for the same device id", async () => {
    const e = small();
    const a = T();
    const b = T();
    for (let i = 0; i < 3; i++) await lim(e, a, "alice");
    expect(await lim(e, a, "alice")).not.toBeNull();
    expect(await lim(e, b, "alice")).toBeNull();
    // A tenant whose name ends the way another's begins does not share a bucket either.
    expect(await lim(e, "x", "yz")).toBeNull();
    for (let i = 0; i < 2; i++) await lim(e, "x", "yz");
    expect(await lim(e, "x", "yz")).not.toBeNull();
    expect(await lim(e, "xy", "z")).toBeNull();
  });

  it("one flooding device cannot lock out the tenant's honest devices; the tenant budget caps all of them together", async () => {
    const e = small();
    const t = T();
    for (let i = 0; i < 500; i++) await lim(e, t, "mallory"); // refused after 3, and the refusals cost the tenant nothing
    for (const d of ["a", "b", "c"]) expect(await lim(e, t, d)).toBeNull();
    // Enough devices together do exhaust the tenant's budget (TENANT_FACTOR times the device's): that is the cap.
    let served = 3 + 3; // mallory's 3 and a, b, c
    for (let i = 0; served < 3 * TENANT_FACTOR; i++, served++) expect(await lim(e, t, `d${i}`)).toBeNull();
    const over = await lim(e, t, "fresh");
    expect(over).not.toBeNull();
    expect(await lim(e, T(), "fresh")).toBeNull(); // other tenants are untouched
  });

  it("uses the defaults when nothing overrides them, and ignores nonsense overrides", async () => {
    const plain = { ...env, RATE_TASK_PER_MIN: undefined, RATE_MESSAGE_PER_MIN: "x", RATE_FIND_PER_MIN: "0" } as Env;
    const t = T();
    for (let i = 0; i < 30; i++) expect(await lim(plain, t, "alice")).toBeNull();
    expect(await lim(plain, t, "alice")).not.toBeNull();
    for (let i = 0; i < 300; i++) expect(await lim(plain, t, "alice", "message")).toBeNull();
    expect(await lim(plain, t, "alice", "message")).not.toBeNull();
    for (let i = 0; i < 60; i++) expect(await lim(plain, t, "alice", "find")).toBeNull();
    expect(await lim(plain, t, "alice", "find")).not.toBeNull();
    for (let i = 0; i < 300; i++) expect(await lim({ ...plain, RATE_PREKEY_PER_MIN: undefined } as Env, t, "alice", "prekey")).toBeNull();
    expect(await lim({ ...plain, RATE_PREKEY_PER_MIN: undefined } as Env, t, "alice", "prekey")).not.toBeNull();
  // ~1000 limiter calls, each a durable storage write (~25 ms on Windows runners): sized for that.
  }, 180_000);

  it("fails closed when the limiter is unavailable", async () => {
    const broken = { ...env, RATE: { get: () => { throw new Error("down"); }, idFromName: () => ({}) } } as unknown as Env;
    expect(await lim(broken, T(), "alice")).toBe(60_000);
  });

  it("names hold no tenant or device id and storage holds two numbers and an alarm", async () => {
    const e = small();
    const t = T();
    await lim(e, t, "alice-device");
    const names: string[] = [];
    const ns = new Proxy(env.RATE, { get: (o, k) => (k === "idFromName" ? (s: string) => (names.push(s), o.idFromName(s)) : (o as any)[k].bind(o)) });
    await lim({ ...e, RATE: ns } as Env, t, "alice-device");
    expect(names).toHaveLength(2); // the device's budget, then the tenant's
    expect(names[0]).toMatch(/^dev-task:[0-9a-f]{32}$/);
    expect(names[1]).toMatch(/^ten-task:[0-9a-f]{32}$/);
    expect(names.join()).not.toContain(t);
    expect(names.join()).not.toContain("alice-device");
    const rl = env.RATE.get(env.RATE.idFromName(names[0]!));
    expect(await runInDurableObject(rl, async (_i, s) => [(await s.storage.list()).size, (await s.storage.getAlarm()) !== null])).toEqual([1, true]);
  });
});

describe("limits on the A2A endpoint", () => {
  let n = 0;
  const x = () => {
    const T = `rla${++n}`;
    return { T, bearer: (d: string) => ({ Authorization: `Bearer dev:${T}:${d}` }) };
  };
  const e = (over: Record<string, string> = {}) => ({ ...env, RATE_TASK_PER_MIN: "3", RATE_MESSAGE_PER_MIN: "3", ...over }) as Env;
  const rpc = (en: Env, w: ReturnType<typeof x>, device: string, method: string, params: unknown) =>
    handleA2A(new Request("https://gw/a2a", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 7, method, params }) }), en, { tenant: w.T, device });
  const send = (en: Env, w: ReturnType<typeof x>, device: string, kind: "TASK" | "REPLY", task: string, to: string) =>
    rpc(en, w, device, "SendMessage", {
      message: {
        messageId: `m${++n}`,
        role: "ROLE_USER",
        parts: [{ raw: b64(encodeWire({ header: header(kind, { tenant: w.T, sender: device, target: to, task: taskBytes(task), seq: kind === "TASK" ? 0 : 1 }), bucket: 4096 })), mediaType: SEALED_MEDIA_TYPE }],
      },
    });
  const expectLimited = async (r: Response) => {
    expect(r.status).toBe(429);
    const body: any = await r.json();
    expect(body).toEqual({ jsonrpc: "2.0", id: 7, error: { code: -32016, message: "rate limited", data: { retry_after_ms: expect.any(Number) } } });
    expect(body.error.data.retry_after_ms).toBeGreaterThan(0);
    expect(body.error.data.retry_after_ms).toBeLessThanOrEqual(60_000);
    expect(r.headers.get("retry-after")).toBe(String(Math.ceil(body.error.data.retry_after_ms / 1000)));
    expect(r.headers.get("cache-control")).toBe("no-store");
  };

  it("refuses new tasks past the budget, before creating anything, and only for that device", async () => {
    const w = x();
    const en = e();
    for (let i = 0; i < 3; i++) {
      const r = await send(en, w, "alice", "TASK", `t${i}`, "bob");
      expect(r.status).toBe(200); // bob is offline: refused as such, but counted
      expect(((await r.json()) as any).error.code).toBe(-32010);
    }
    await expectLimited(await send(en, w, "alice", "TASK", "over", "bob"));
    const got = await rpc(env as Env, w, "alice", "GetTask", { id: taskHex("over") });
    expect(((await got.json()) as any).error.code).toBe(-32001); // never created
    expect((await send(en, w, "carol", "TASK", "c1", "bob")).status).toBe(200);
  });

  it("a flood aimed at one connected target is refused at the gateway before it reaches the target, and the honest caller is still served", async () => {
    const w = x();
    const res = await gw("https://gw/v1/connect", { headers: { Upgrade: "websocket", ...w.bearer("bob") } });
    const ws = res.webSocket!;
    ws.accept();
    const events: any[] = [];
    let welcomed: () => void;
    const ready = new Promise<void>((r) => (welcomed = r));
    ws.addEventListener("message", (ev) => {
      const m = JSON.parse(ev.data as string);
      if (m.t === "welcome") welcomed();
      else events.push(m);
    });
    ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
    await ready;

    const en = e();
    let delivered = 0;
    let refused = 0;
    for (let i = 0; i < 12; i++) {
      const r = await send(en, w, "mallory", "TASK", `f${i}`, "bob");
      if (r.status === 429) refused++;
      else if (((await r.json()) as any).result) delivered++;
    }
    expect([delivered, refused]).toEqual([3, 9]);
    await new Promise((r) => setTimeout(r, 100)); // let what is in flight arrive
    expect(events).toHaveLength(delivered); // the target saw exactly what was let through
    // An honest caller to the same target is served, and the target's own replies are not held up.
    expect(((await (await send(en, w, "alice", "TASK", "honest", "bob")).json()) as any).result).toBeDefined();
    expect((await send(en, w, "bob", "REPLY", "r1", "mallory")).status).toBe(200);
    ws.close();
  });

  it("limits the other messages, GetTask and CancelTask on their own budget", async () => {
    const w = x();
    const en = e();
    for (let i = 0; i < 3; i++) await send(en, w, "alice", "REPLY", `r${i}`, "bob");
    await expectLimited(await send(en, w, "alice", "REPLY", "r1", "bob"));
    await expectLimited(await rpc(en, w, "alice", "GetTask", { id: taskHex("r1") }));
    const cancel = {
      id: taskHex("r1"),
      metadata: { parley: { messageId: "c1", parts: [{ raw: b64(encodeWire({ header: header("CANCEL", { tenant: w.T, sender: "alice", target: "bob", task: taskBytes("r1"), seq: 1 }), bucket: 4096 })), mediaType: SEALED_MEDIA_TYPE }] } },
    };
    await expectLimited(await rpc(en, w, "alice", "CancelTask", cancel));
    expect((await send(en, w, "alice", "TASK", "t1", "bob")).status).toBe(200); // the task budget is separate
  });

  it("does not spend budget on a request that is malformed", async () => {
    const w = x();
    const en = e();
    for (let i = 0; i < 10; i++) expect((await rpc(en, w, "alice", "GetTask", { id: "nope" })).status).toBe(200);
    expect(await limitDevice(en, w.T, "alice", "message")).toBeNull();
  });

  it("fails closed: with the limiter down a send is refused and nothing is created", async () => {
    const w = x();
    const broken = { ...env, RATE: { get: () => { throw new Error("down"); }, idFromName: () => ({}) } } as unknown as Env;
    await expectLimited(await send(broken, w, "alice", "TASK", "t1", "bob"));
    expect(((await (await rpc(env as Env, w, "alice", "GetTask", { id: taskHex("t1") })).json()) as any).error.code).toBe(-32001);
  });
});

describe("limits on the directory", () => {
  const testDevice: DeviceAuth = async (req) => {
    const m = /^Bearer dev:([^:]+):([^:]+)$/.exec(req.headers.get("Authorization") ?? "");
    return m ? { tenant: m[1]!, device: m[2]! } : null;
  };
  const find = (en: Env, t: string, d: string, body: unknown = {}) =>
    handleDirectory(new Request("https://gw/v1/directory/find", { method: "POST", headers: { Authorization: `Bearer dev:${t}:${d}` }, body: JSON.stringify(body) }), en, testDevice);

  it("find is limited per device with a Retry-After, and a bad query is refused before it costs anything", async () => {
    const en = { ...env, RATE_FIND_PER_MIN: "2" } as Env;
    const t = "rld1";
    const [a, b] = ["a".repeat(32), "b".repeat(32)];
    expect((await find(en, t, a, { limit: 0 })).status).toBe(400);
    expect((await find(en, t, a)).status).not.toBe(429);
    expect((await find(en, t, a)).status).not.toBe(429);
    const r = await find(en, t, a);
    expect(r.status).toBe(429);
    const wait = Number(r.headers.get("retry-after"));
    expect(wait).toBeGreaterThan(0);
    expect(wait).toBeLessThanOrEqual(60);
    expect(await r.json()).toEqual({ error: "rate_limited", retry_after_ms: wait * 1000 });
    expect((await find(en, t, b)).status).not.toBe(429);
    expect((await find(en, "rld2", a)).status).not.toBe(429);
  });
});

describe("the window arithmetic", () => {
  const W = 1500;
  it("starts a window, counts to the limit, then refuses without counting", () => {
    let r = advance(undefined, 2, W, 1000);
    expect(r).toEqual({ w: { start: 1000, n: 1, windowMs: W }, ok: true, retryAfterS: 2 });
    r = advance(r.w, 2, W, 1100);
    expect(r).toEqual({ w: { start: 1000, n: 2, windowMs: W }, ok: true, retryAfterS: 2 });
    const refused = advance(r.w, 2, W, 1200);
    expect(refused).toEqual({ w: { start: 1000, n: 2, windowMs: W }, ok: false, retryAfterS: 2 }); // n did not grow
    expect(r.w.n).toBe(2); // the input is not changed
  });

  it("is exact at the boundary: the last millisecond is in the window, the end is a new one", () => {
    const w = { start: 1000, n: 2, windowMs: W };
    expect(advance(w, 2, W, 2499).ok).toBe(false);
    expect(advance(w, 2, W, 2500)).toEqual({ w: { start: 2500, n: 1, windowMs: W }, ok: true, retryAfterS: 2 });
  });

  it("rounds the wait up to whole seconds, at least 1 and at most one window", () => {
    const w = { start: 0, n: 5, windowMs: 60_000 };
    expect(advance(w, 5, 60_000, 59_999).retryAfterS).toBe(1); // 1 ms left
    expect(advance(w, 5, 60_000, 59_000).retryAfterS).toBe(1); // exactly 1 s left
    expect(advance(w, 5, 60_000, 58_999).retryAfterS).toBe(2); // 1.001 s left
    expect(advance(w, 5, 60_000, 1).retryAfterS).toBe(60);
    expect(advance({ start: 10 ** 9, n: 5, windowMs: 60_000 }, 5, 60_000, 0).retryAfterS).toBe(60); // a clock set far back
    expect(advance({ start: 100, n: 5, windowMs: 1500 }, 5, 1500, 99).retryAfterS).toBe(2);
  });

  it("re-arms for a window that is still open and deletes otherwise", () => {
    expect(reArm(undefined, 0)).toBeNull();
    const w = { start: 1000, n: 1, windowMs: 500 };
    expect(reArm(w, 1499)).toBe(1500);
    expect(reArm(w, 1500)).toBeNull();
  });

  it("limitFor takes whole numbers above zero and nothing else", () => {
    expect(limitFor("7", 3)).toBe(7);
    for (const v of [undefined, "", "0", "-1", "2.5", "x", "NaN", "Infinity"]) expect(limitFor(v, 3), String(v)).toBe(3);
  });
});

describe("the DO keeps one row and one alarm at the window's end", () => {
  it("sets the alarm at the end of the window, not before it", async () => {
    const id = env.RATE.idFromName("alarm-unit");
    await env.RATE.get(id).hit(5, 40_000);
    const stub: DurableObjectStub = env.RATE.get(id);
    const row = await runInDurableObject(stub, async (_i, s) => ({ start: ((await s.storage.get("w")) as { start: number }).start, alarm: await s.storage.getAlarm() }));
    expect(row.alarm).toBe(row.start + 40_000);
    const after = await runInDurableObject(stub, async (i, s) => {
      await (i as unknown as { alarm(): Promise<void> }).alarm(); // fired early: the row stays and the alarm is set again for the same end
      return { row: (await s.storage.get("w")) !== undefined, alarm: await s.storage.getAlarm() };
    });
    expect(after).toEqual({ row: true, alarm: row.start + 40_000 });
  });
});

describe("login and session budgets", () => {
  const hex = async (s: string) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))).slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const run = async (e: Env, path: string, headers: Record<string, string> = {}, method = "GET") => {
    const { default: worker } = await import("../src/index");
    return worker.fetch(new Request(`https://gw${path}`, { method, headers }), e);
  };
  const spy = (names: string[]) => ({ ...env, RATE: new Proxy(env.RATE, { get: (o, k) => (k === "idFromName" ? (s: string) => (names.push(s), o.idFromName(s)) : (o as any)[k].bind(o)) }) }) as Env;

  it("a refusal is JSON, uncached, with Retry-After", async () => {
    const e = { ...env, RATE_SESSION_PER_MIN: "1" } as Env;
    await run(e, "/v1/session", { "CF-Connecting-IP": "203.0.113.9" }, "POST");
    const r = await run(e, "/v1/session", { "CF-Connecting-IP": "203.0.113.9" }, "POST");
    expect(r.status).toBe(429);
    expect(r.headers.get("content-type")).toBe("application/json");
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("retry-after")).toMatch(/^([1-9]|[1-5][0-9]|60)$/);
  });

  it("auth, tenant and session budgets are separate, even when the key is the same string", async () => {
    const e = { ...env, RATE_AUTH_PER_MIN: "2", RATE_TENANT_LOGIN_PER_MIN: "1", RATE_SESSION_PER_MIN: "1" } as Env;
    const ip = { "CF-Connecting-IP": "sharedkey" };
    // the login counts once against auth[ip] and once against tenant[sharedkey]: both fit
    expect((await run(e, "/auth/google/login?tenant=sharedkey&role=user", ip)).status).not.toBe(429);
    expect((await run(e, "/v1/session", ip, "POST")).status).toBe(401); // the session budget is its own
    expect((await run(e, "/v1/session", ip, "POST")).status).toBe(429);
  });

  it("only a login counts against the tenant, and only a well-formed tenant name", async () => {
    const e = { ...env, RATE_TENANT_LOGIN_PER_MIN: "1" } as Env;
    const n = (i: number) => ({ "CF-Connecting-IP": `198.51.100.${i}` });
    for (let i = 1; i <= 3; i++) expect((await run(e, "/auth/google/callback?tenant=acme", n(i))).status).not.toBe(429);
    for (const [i, bad] of ["bad tenant", "a".repeat(65), "x!", "!x"].entries()) {
      for (let k = 0; k < 2; k++) expect((await run(e, `/auth/google/login?tenant=${encodeURIComponent(bad)}&role=user`, n(10 + i * 2 + k))).status, bad).not.toBe(429);
    }
    expect((await run(e, `/auth/google/login?tenant=${"a".repeat(64)}`, n(40))).status).not.toBe(429);
    expect((await run(e, `/auth/google/login?tenant=${"a".repeat(64)}`, n(41))).status).toBe(429);
  });

  it("names are scope plus a hash: the source or tenant is not in them, the tenant is case-folded, and no header means one shared 'unknown'", async () => {
    const names: string[] = [];
    const e = spy(names);
    await run(e, "/auth/google/login?tenant=AcMe&role=user", { "CF-Connecting-IP": "203.0.113.7" });
    await run(e, "/v1/session", {}, "POST");
    await run(e, "/auth/google/callback", {});
    await run(e, "/v1/connect/token", { "CF-Connecting-IP": "203.0.113.7" }, "POST");
    expect(names).toEqual([`auth:${await hex("203.0.113.7")}`, `tenant:${await hex("acme")}`, `session:${await hex("unknown")}`, `auth:${await hex("unknown")}`, `connect:${await hex("203.0.113.7")}`]);
    expect(names.join()).not.toContain("203.0.113.7");
  });
});
