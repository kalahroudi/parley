// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import { SEALED_MEDIA_TYPE } from "../src/a2a";
import { POLICIES, TENANT_POLICIES, clientAddress, sourceKey, take, tooMany, type Bucket, type Policy } from "../src/ratelimit";
import { BUCKET_FULL_RETRY_MS, MAX_BUCKETS } from "../src/tenant";
import { b64, encodeWire, header, taskBytes, taskHex } from "./wire";

const P: Policy = { capacity: 3, refillPerSec: 0.5 };

describe("token bucket arithmetic", () => {
  it("starts full, spends one token a request and says when it is full again", () => {
    const d = take(undefined, 1000, P);
    expect(d).toEqual({ ok: true, bucket: { tokens: 2, at: 1000 }, full_at: 1000 + 2000 });
  });

  it("refuses when empty, says how long until one token, and changes nothing", () => {
    let b: Bucket | undefined;
    for (let i = 0; i < 3; i++) {
      const d = take(b, 0, P);
      expect(d.ok).toBe(true);
      b = d.ok ? d.bucket : b;
    }
    expect(b).toEqual({ tokens: 0, at: 0 });
    expect(take(b, 0, P)).toEqual({ ok: false, retry_after_ms: 2000 });
    expect(take(b, 500, P)).toEqual({ ok: false, retry_after_ms: 1500 }); // 0.25 token back, 0.75 to go
    expect(b).toEqual({ tokens: 0, at: 0 });
  });

  it("refills with time and spends exactly one token at the boundary", () => {
    expect(take({ tokens: 0, at: 0 }, 2000, P)).toEqual({ ok: true, bucket: { tokens: 0, at: 2000 }, full_at: 2000 + 6000 });
    expect(take({ tokens: 0, at: 0 }, 1999, P).ok).toBe(false);
    expect(take({ tokens: 1, at: 5 }, 5, P).ok).toBe(true);
  });

  it("never holds more than its capacity, however long it sat idle", () => {
    expect(take({ tokens: 0, at: 0 }, 10 ** 9, P)).toEqual({ ok: true, bucket: { tokens: 2, at: 10 ** 9 }, full_at: 10 ** 9 + 2000 });
  });

  it("a clock that went backwards refills nothing and does not drain the bucket", () => {
    expect(take({ tokens: 1.25, at: 1000 }, 0, { capacity: 3, refillPerSec: 5 })).toEqual({ ok: true, bucket: { tokens: 0.25, at: 0 }, full_at: 0 + 550 });
  });

  it("pins the limits", () => {
    expect(POLICIES).toEqual({
      task: { capacity: 20, refillPerSec: 0.5 },
      message: { capacity: 100, refillPerSec: 5 },
      find: { capacity: 30, refillPerSec: 1 },
      presence: { capacity: 60, refillPerSec: 2 },
      login: { capacity: 10, refillPerSec: 1 / 6 },
      enroll: { capacity: 20, refillPerSec: 1 / 30 },
      status: { capacity: 30, refillPerSec: 0.5 },
      session: { capacity: 30, refillPerSec: 0.5 },
    });
    expect(TENANT_POLICIES).toEqual({
      task: { capacity: 400, refillPerSec: 10 },
      enroll: { capacity: 60, refillPerSec: 1 },
      status: { capacity: 300, refillPerSec: 10 },
    });
  });
});

describe("source keys and the refusal", () => {
  it("hashes a source with a salt: stable, 128 bits, different per salt and per value, never the value", async () => {
    const k = await sourceKey("salt-a|t1", "203.0.113.9");
    expect(k).toMatch(/^[0-9a-f]{32}$/);
    expect(await sourceKey("salt-a|t1", "203.0.113.9")).toBe(k);
    expect(await sourceKey("salt-a|t2", "203.0.113.9")).not.toBe(k);
    expect(await sourceKey("salt-a|t1", "203.0.113.10")).not.toBe(k);
    expect(k).not.toContain("203");
  });

  it("is HMAC-SHA256 truncated to 16 bytes, zero-padded per byte, and the key is not extractable", async () => {
    // Computed with node:crypto: createHmac("sha256", "salt|t1").update("value4"); it has a byte below 0x10.
    const spy = vi.spyOn(crypto.subtle, "importKey");
    expect(await sourceKey("salt|t1", "value4")).toBe("5f42fa0d4816c9e1cd09c0335eca8acc");
    expect(spy.mock.calls[0]![3]).toBe(false);
    spy.mockRestore();
  });

  it("reads the Cloudflare client address, or \"none\"", () => {
    expect(clientAddress(new Request("https://gw/", { headers: { "CF-Connecting-IP": "192.0.2.1" } }))).toBe("192.0.2.1");
    expect(clientAddress(new Request("https://gw/"))).toBe("none");
  });

  it("answers 429 with the exact wait and a whole-second Retry-After that is never zero", async () => {
    for (const [ms, secs] of [[0, "1"], [1, "1"], [1000, "1"], [1001, "2"], [6000, "6"]] as const) {
      const r = tooMany(ms);
      expect(r.status).toBe(429);
      expect(r.headers.get("retry-after")).toBe(secs);
      expect(r.headers.get("cache-control")).toBe("no-store");
      expect(r.headers.get("content-type")).toBe("application/json");
      expect(await r.json()).toEqual({ error: "rate_limited", retry_after_ms: ms });
    }
  });
});

let n = 0;
const tenant = () => {
  const T = `rl${++n}`;
  return { T, stub: env.TENANT.get(env.TENANT.idFromName(T)), bearer: (d: string) => ({ Authorization: `Bearer dev:${T}:${d}` }) };
};
const call = (x: { stub: DurableObjectStub }, method: string, ...args: unknown[]): Promise<any> => runInDurableObject(x.stub, async (i) => (i as any)[method](...args));
// An empty bucket whose clock is an hour ahead: nothing refills while a test runs.
const empty = (x: { stub: DurableObjectStub }, scope: string, subject: string) =>
  runInDurableObject(x.stub, async (_i, s) => void (await s.storage.put(`rl:${scope}:${subject}`, { tokens: 0, at: Date.now() + 3_600_000, full_at: Date.now() + 7_200_000 } satisfies Bucket & { full_at: number })));
const drain = async (x: { stub: DurableObjectStub }, scope: string, subject: string, times: number) => {
  for (let i = 0; i < times; i++) expect(await call(x, "rateLimit", scope, subject)).toEqual({ ok: true });
};

describe("the Tenant DO's counters", () => {
  it("allows the burst, then refuses with a wait time, per scope and per subject", async () => {
    const x = tenant();
    await drain(x, "task", "alice", POLICIES.task.capacity);
    const r = await call(x, "rateLimit", "task", "alice");
    expect(r.ok).toBe(false);
    expect(r.retry_after_ms).toBeGreaterThan(1500);
    expect(r.retry_after_ms).toBeLessThanOrEqual(2000);
    expect(await call(x, "rateLimit", "task", "bob")).toEqual({ ok: true }); // another device
    expect(await call(x, "rateLimit", "message", "alice")).toEqual({ ok: true }); // another scope
  });

  it("a tenant-wide counter limits all sources together, and a refusal charges neither counter", async () => {
    const x = tenant();
    const keys = () => runInDurableObject(x.stub, async (_i, st) => [...(await st.storage.list<Bucket>({ prefix: "rl:" }))].sort());
    expect(await call(x, "rateLimit", "enroll", "s1")).toEqual({ ok: true });
    expect((await keys()).map(([k]) => k)).toEqual(["rl:enroll:*", "rl:enroll:s1"]);
    await empty(x, "enroll", "*");
    const denied = await call(x, "rateLimit", "enroll", "s2");
    expect(denied.ok).toBe(false);
    expect(denied.retry_after_ms).toBeGreaterThan(0);
    expect((await keys()).map(([k]) => k)).toEqual(["rl:enroll:*", "rl:enroll:s1"]); // s2 was not charged (or created)
    // The other way round: the source is empty, the tenant counter has room and is not charged.
    const y = tenant();
    await drain(y, "enroll", "s1", POLICIES.enroll.capacity);
    const before = await runInDurableObject(y.stub, (_i, st) => st.storage.get<Bucket>("rl:enroll:*"));
    expect((await call(y, "rateLimit", "enroll", "s1")).ok).toBe(false);
    expect(await runInDurableObject(y.stub, (_i, st) => st.storage.get<Bucket>("rl:enroll:*"))).toEqual(before);
  });

  it("the wait is the longer of the two counters', and a scope with no tenant-wide counter has none", async () => {
    const x = tenant();
    // Source empty (30 s to a token), tenant-wide empty (1 s): the source decides.
    await call(x, "rateLimit", "enroll", "s1");
    await empty(x, "enroll", "*");
    await empty(x, "enroll", "s1");
    expect((await call(x, "rateLimit", "enroll", "s1")).retry_after_ms).toBe(30_000);
    // Source nearly full of tokens (20 ms), tenant-wide empty (100 ms): the tenant decides.
    await call(x, "rateLimit", "status", "s1");
    await empty(x, "status", "*");
    await runInDurableObject(x.stub, async (_i, st) => void (await st.storage.put("rl:status:s1", { tokens: 0.99, at: Date.now() + 3_600_000, full_at: 0 })));
    expect((await call(x, "rateLimit", "status", "s1")).retry_after_ms).toBe(100);
    expect(await call(x, "rateLimit", "login", "src")).toEqual({ ok: true });
    expect(await runInDurableObject(x.stub, (_i, st) => st.storage.get("rl:login:*"))).toBeUndefined();
  });

  it("counters are per tenant", async () => {
    const a = tenant();
    const b = tenant();
    await drain(a, "task", "alice", POLICIES.task.capacity);
    expect((await call(a, "rateLimit", "task", "alice")).ok).toBe(false);
    expect(await call(b, "rateLimit", "task", "alice")).toEqual({ ok: true });
  });

  it("forgets a bucket once it has refilled, and keeps (and re-arms for) one that has not", async () => {
    const x = tenant();
    await drain(x, "presence", "spent", 1);
    await drain(x, "presence", "old", 1);
    const keys = () => runInDurableObject(x.stub, async (_i, s) => [...(await s.storage.list({ prefix: "rl:" })).keys()].sort());
    expect(await keys()).toEqual(["rl:presence:old", "rl:presence:spent"]);
    const full = Date.now() + 3_600_000;
    await runInDurableObject(x.stub, async (_i, s) => {
      await s.storage.put("rl:presence:old", { tokens: 0, at: 0, full_at: Date.now() - 1 });
      await s.storage.put("rl:presence:spent", { tokens: 0, at: 0, full_at: full });
      await s.storage.setAlarm(Date.now() + 10);
    });
    expect(await runDurableObjectAlarm(x.stub)).toBe(true);
    expect(await keys()).toEqual(["rl:presence:spent"]);
    expect(await runInDurableObject(x.stub, (_i, s) => s.storage.getAlarm())).toBe(full);
  });

  it("at the cap a caller with no bucket is refused, one with a bucket is served, and a freed slot is reusable", async () => {
    const x = tenant();
    await drain(x, "presence", "known", 1);
    await runInDurableObject(x.stub, async (_i, s) => {
      const fill: Record<string, unknown> = {};
      for (let i = 0; i < MAX_BUCKETS - 1; i++) {
        fill[`rl:find:filler${i}`] = { tokens: 0, at: 0, full_at: Date.now() + 3_600_000 };
        if (Object.keys(fill).length === 128) {
          await s.storage.put(fill);
          for (const k of Object.keys(fill)) delete fill[k];
        }
      }
      await s.storage.put(fill);
    });
    expect(await call(x, "rateLimit", "presence", "new")).toEqual({ ok: false, retry_after_ms: BUCKET_FULL_RETRY_MS });
    expect(await call(x, "rateLimit", "presence", "known")).toEqual({ ok: true });
    await runInDurableObject(x.stub, (_i, s) => s.storage.delete("rl:find:filler0"));
    expect(await call(x, "rateLimit", "presence", "new")).toEqual({ ok: true });
  });
});

describe("limits on the A2A endpoint", () => {
  const T0 = () => ({ ...tenant() });
  const send = (x: ReturnType<typeof T0>, device: string, kind: "TASK" | "REPLY", task: string, to: string) =>
    SELF.fetch("https://gw/a2a", {
      method: "POST",
      headers: x.bearer(device),
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 7,
        method: "SendMessage",
        params: {
          message: {
            messageId: `m${++n}`,
            role: "ROLE_USER",
            parts: [{ raw: b64(encodeWire({ header: header(kind, { tenant: x.T, sender: device, target: to, task: taskBytes(task), seq: kind === "TASK" ? 0 : 1 }), bucket: 4096 })), mediaType: SEALED_MEDIA_TYPE }],
          },
        },
      }),
    });
  const expectLimited = async (r: Response, minMs: number, maxMs: number) => {
    expect(r.status).toBe(429);
    const body: any = await r.json();
    expect(body).toEqual({ jsonrpc: "2.0", id: 7, error: { code: -32016, message: "rate limited", data: { retry_after_ms: expect.any(Number) } } });
    expect(body.error.data.retry_after_ms).toBeGreaterThan(minMs);
    expect(body.error.data.retry_after_ms).toBeLessThanOrEqual(maxMs);
    expect(r.headers.get("retry-after")).toBe(String(Math.ceil(body.error.data.retry_after_ms / 1000)));
    expect(r.headers.get("cache-control")).toBe("no-store");
  };

  it("refuses new tasks past the burst, before creating anything, and only for that device", async () => {
    const x = T0();
    for (let i = 0; i < POLICIES.task.capacity; i++) {
      const r = await send(x, "alice", "TASK", `t${i}`, "bob");
      expect(r.status).toBe(200); // bob is offline: the task is refused as such, but it was counted
      expect(((await r.json()) as any).error.code).toBe(-32010);
    }
    await expectLimited(await send(x, "alice", "TASK", "over", "bob"), 0, 2000); // the bucket may have refilled a little while we sent
    const tasks = await SELF.fetch("https://gw/a2a", { method: "POST", headers: x.bearer("alice"), body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "GetTask", params: { id: taskHex("over") } }) });
    expect(((await tasks.json()) as any).error.code).toBe(-32001); // never created
    expect((await send(x, "carol", "TASK", "c1", "bob")).status).toBe(200);
  });

  it("a flood aimed at one connected target is refused at the gateway before it reaches the target", async () => {
    const x = T0();
    const res = await SELF.fetch("https://gw/v1/connect", { headers: { Upgrade: "websocket", ...x.bearer("bob") } });
    const ws = res.webSocket!;
    ws.accept();
    const events: any[] = [];
    let welcomed: () => void;
    const ready = new Promise<void>((r) => (welcomed = r));
    ws.addEventListener("message", (e) => {
      const m = JSON.parse(e.data as string);
      if (m.t === "welcome") welcomed();
      else events.push(m);
    });
    ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
    await ready;

    const flood = POLICIES.task.capacity * 3;
    const started = Date.now();
    let delivered = 0;
    let refused = 0;
    for (let i = 0; i < flood; i++) {
      const r = await send(x, "mallory", "TASK", `f${i}`, "bob");
      if (r.status === 429) refused++;
      else if (r.status === 200 && ((await r.json()) as any).result) delivered++;
    }
    const allowed = POLICIES.task.capacity + Math.floor(((Date.now() - started) / 1000) * POLICIES.task.refillPerSec) + 1; // the burst plus what refilled meanwhile
    expect(delivered).toBeGreaterThanOrEqual(POLICIES.task.capacity);
    expect(delivered).toBeLessThanOrEqual(allowed);
    expect(refused).toBe(flood - delivered);
    // Wait for the events already in flight to arrive, then count: the target saw exactly what was delivered.
    await new Promise((r) => setTimeout(r, 100));
    expect(events).toHaveLength(delivered);
    // The target's own replies are not held up by the caller's flood.
    expect((await send(x, "bob", "REPLY", "r1", "mallory")).status).toBe(200);
    ws.close();
  });

  it("limits the other messages, GetTask and CancelTask on their own allowance", async () => {
    const x = T0();
    await empty(x, "message", "alice");
    await expectLimited(await send(x, "alice", "REPLY", "r1", "bob"), 0, 200);
    const rpc = (method: string, params: unknown) => SELF.fetch("https://gw/a2a", { method: "POST", headers: x.bearer("alice"), body: JSON.stringify({ jsonrpc: "2.0", id: 7, method, params }) });
    await expectLimited(await rpc("GetTask", { id: taskHex("r1") }), 0, 200);
    const cancel = {
      id: taskHex("r1"),
      metadata: { parley: { messageId: "c1", parts: [{ raw: b64(encodeWire({ header: header("CANCEL", { tenant: x.T, sender: "alice", target: "bob", task: taskBytes("r1"), seq: 1 }), bucket: 4096 })), mediaType: SEALED_MEDIA_TYPE }] } },
    };
    await expectLimited(await rpc("CancelTask", cancel), 0, 200);
    expect((await send(x, "alice", "TASK", "t1", "bob")).status).toBe(200); // the task allowance is separate
  });

  it("does not spend allowance on a request that is malformed", async () => {
    const x = T0();
    for (let i = 0; i < POLICIES.message.capacity + 5; i++) {
      const r = await SELF.fetch("https://gw/a2a", { method: "POST", headers: x.bearer("alice"), body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "GetTask", params: { id: "nope" } }) });
      expect(r.status).toBe(200);
    }
    expect(await call(x, "rateLimit", "message", "alice")).toEqual({ ok: true });
  });
});

describe("limits on the directory, and presence", () => {
  const post = (x: ReturnType<typeof tenant>, path: string, body: unknown, auth: string) =>
    SELF.fetch(`https://gw${path}`, { method: "POST", headers: { "content-type": "application/json", Authorization: auth }, body: JSON.stringify(body) });
  const key = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  const admin = (x: { T: string }) => `Bearer dev-admin:${x.T}`;
  async function enroll(x: ReturnType<typeof tenant>, email: string) {
    const sk = key();
    const { id } = (await (await post(x, "/v1/enroll/request", { name: "laptop", signing_key: sk }, `Bearer dev-user:${x.T}:${email}`)).json()) as any;
    await post(x, "/v1/admin/enrollments/decide", { id, decision: "approved" }, admin(x));
    await post(x, "/v1/admin/bindings", { id, binding: { device_id: id, signing_key: sk, version: 1 } }, admin(x));
    return { id, auth: `Bearer dev:${x.T}:${id}` };
  }
  async function online(x: ReturnType<typeof tenant>, auth: string) {
    const res = await SELF.fetch("https://gw/v1/connect", { headers: { Upgrade: "websocket", Authorization: auth } });
    const ws = res.webSocket!;
    ws.accept();
    const welcome = new Promise<void>((r) => ws.addEventListener("message", () => r(), { once: true }));
    ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
    await welcome;
    return ws;
  }
  const publish = async (d: { auth: string }, x: ReturnType<typeof tenant>, visibility?: string) =>
    ((await (await post(x, "/v1/cards/publish", { card: { name: "Reviewer", description: "d", tags: [], examples: [], ...(visibility ? { visibility } : {}) } }, d.auth)).json()) as any).id as string;

  it("find is limited per device with a Retry-After", async () => {
    const x = tenant();
    const a = await enroll(x, "a@example.test");
    expect((await post(x, "/v1/directory/find", {}, a.auth)).status).toBe(200);
    await empty(x, "find", a.id);
    const r = await post(x, "/v1/directory/find", {}, a.auth);
    expect(r.status).toBe(429);
    expect(r.headers.get("retry-after")).toBe("1");
    expect(await r.json()).toEqual({ error: "rate_limited", retry_after_ms: expect.any(Number) });
    const b = await enroll(x, "b@example.test");
    expect((await post(x, "/v1/directory/find", {}, b.auth)).status).toBe(200);
  });

  it("presence says whether a visible bot's device is connected", async () => {
    const x = tenant();
    const alice = await enroll(x, "alice@example.test");
    const bob = await enroll(x, "bob@example.test");
    const id = await publish(bob, x);
    const ask = async () => ({ status: 0, ...(await (await post(x, "/v1/directory/presence", { id }, alice.auth)).json()) as any });
    expect(await ask()).toEqual({ status: 0, online: false });
    const ws = await online(x, bob.auth);
    expect((await ask()).online).toBe(true);
    ws.close();
  });

  it("presence is not_found for an unknown, malformed or hidden card, and for a caller that is not enrolled", async () => {
    const x = tenant();
    const alice = await enroll(x, "alice@example.test");
    const bob = await enroll(x, "bob@example.test");
    const hidden = await publish(bob, x, "private");
    expect(hidden).toMatch(/^[0-9a-f]{32}:[0-9a-f]{16}$/); // it exists; alice just may not see it
    const code = async (id: unknown, auth = alice.auth) => (await post(x, "/v1/directory/presence", { id }, auth)).status;
    expect(await code(hidden)).toBe(404);
    expect(await code(`${bob.id}:${"0".repeat(16)}`)).toBe(404);
    expect(await code(42)).toBe(404);
    expect(await code(hidden, `Bearer dev:${x.T}:${"f".repeat(32)}`)).toBe(404);
    expect(await code(hidden, admin(x))).toBe(401);
  });

  it("presence is limited per device", async () => {
    const x = tenant();
    const alice = await enroll(x, "alice@example.test");
    expect((await post(x, "/v1/directory/presence", { id: "x" }, alice.auth)).status).toBe(404);
    await empty(x, "presence", alice.id);
    const r = await post(x, "/v1/directory/presence", { id: "x" }, alice.auth);
    expect(r.status).toBe(429);
    expect((await r.json()) as any).toEqual({ error: "rate_limited", retry_after_ms: expect.any(Number) });
  });
});

describe("limits on enrollment", () => {
  const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
    SELF.fetch(`https://gw${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
  const salted = (T: string, who: string) => sourceKey(`test-flow-secret|${T}`, who);
  const key = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  const emptyFor = async (x: ReturnType<typeof tenant>, scope: string, who: string) => empty(x, scope, await salted(x.T, who));

  it("limits enrollment requests per user, then refuses with the wait, and others are unaffected", async () => {
    const x = tenant();
    const as = (email: string) => ({ Authorization: `Bearer dev-user:${x.T}:${email}` });
    expect((await post("/v1/enroll/request", { name: "laptop", signing_key: key() }, as("Alice@Example.test"))).status).toBe(202);
    await emptyFor(x, "enroll", "alice@example.test"); // keyed by the lowercased email
    const r = await post("/v1/enroll/request", { name: "laptop", signing_key: key() }, as("ALICE@example.test"));
    expect(r.status).toBe(429);
    expect(await r.json()).toEqual({ error: "rate_limited", retry_after_ms: expect.any(Number) });
    expect(r.headers.get("retry-after")).toMatch(/^[1-9][0-9]*$/);
    expect((await post("/v1/enroll/request", { name: "laptop", signing_key: key() }, as("bob@example.test"))).status).toBe(202);
  });

  it("limits pod-token attempts and status polls per client address", async () => {
    const x = tenant();
    const ip = { "CF-Connecting-IP": "192.0.2.77" };
    expect((await post("/v1/enroll/request", { tenant: x.T, token: "pet_wrong", name: "pod", signing_key: key() }, ip)).status).toBe(401);
    await emptyFor(x, "enroll", "192.0.2.77");
    expect((await post("/v1/enroll/request", { tenant: x.T, token: "pet_wrong", name: "pod", signing_key: key() }, ip)).status).toBe(429);
    expect((await post("/v1/enroll/request", { tenant: x.T, token: "pet_wrong", name: "pod", signing_key: key() }, { "CF-Connecting-IP": "192.0.2.78" })).status).toBe(401);

    expect((await post("/v1/enroll/status", { tenant: x.T, id: "a", poll: "b" }, ip)).status).toBe(404);
    await emptyFor(x, "status", "192.0.2.77");
    const r = await post("/v1/enroll/status", { tenant: x.T, id: "a", poll: "b" }, ip);
    expect(r.status).toBe(429);
    expect((await post("/v1/enroll/status", { tenant: x.T, id: "a", poll: "b" }, { "CF-Connecting-IP": "192.0.2.78" })).status).toBe(404);
  });

  it("a malformed request is refused before it is counted, and the tenant counters hold across sources", async () => {
    const x = tenant();
    expect((await post("/v1/enroll/request", { tenant: "bad tenant!", token: "t" })).status).toBe(400);
    expect(await runInDurableObject(x.stub, (_i, st) => st.storage.list({ prefix: "rl:" }).then((m) => m.size))).toBe(0);
    await empty(x, "status", "*");
    expect((await post("/v1/enroll/status", { tenant: x.T, id: "a", poll: "b" }, { "CF-Connecting-IP": "198.51.100.1" })).status).toBe(429);
  });

  it("stores neither the address nor the email, only salted hashes", async () => {
    const x = tenant();
    await post("/v1/enroll/request", { name: "laptop", signing_key: key() }, { Authorization: `Bearer dev-user:${x.T}:carol@example.test`, "CF-Connecting-IP": "192.0.2.99" });
    await post("/v1/enroll/status", { tenant: x.T, id: "a", poll: "b" }, { "CF-Connecting-IP": "192.0.2.99" });
    const dump = await runInDurableObject(x.stub, async (_i, st) => JSON.stringify([...(await st.storage.list({ prefix: "rl:" }))]));
    expect(dump).not.toContain("192.0.2.99");
    expect(dump).not.toContain("carol");
    expect(dump).toContain(await salted(x.T, "carol@example.test"));
  });
});

describe("limits on sign-in", () => {
  const login = (ip?: string) => SELF.fetch("https://gw/auth/google/login", { headers: ip ? { "CF-Connecting-IP": ip } : {} });

  it("allows a burst per client address, then refuses, and other addresses are unaffected", async () => {
    const ip = `192.0.2.${++n % 250}`;
    for (let i = 0; i < POLICIES.login.capacity; i++) expect((await login(ip)).status).toBe(404); // no provider configured here: past the limiter
    const r = await login(ip);
    expect(r.status).toBe(429);
    expect(r.headers.get("retry-after")).toBe("6");
    expect(await r.json()).toEqual({ error: "rate_limited", retry_after_ms: expect.any(Number) });
    expect((await login(`198.51.100.${n % 250}`)).status).toBe(404);
  });

  it("requests with no address share one bucket", async () => {
    for (let i = 0; i < POLICIES.login.capacity; i++) await login();
    expect((await login()).status).toBe(429);
  });
});
