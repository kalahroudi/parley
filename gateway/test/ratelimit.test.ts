// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { SEALED_MEDIA_TYPE } from "../src/a2a";
import { POLICIES, take, type Bucket, type Policy } from "../src/ratelimit";
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
    });
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

  it("counters are per tenant", async () => {
    const a = tenant();
    const b = tenant();
    await drain(a, "task", "alice", POLICIES.task.capacity);
    expect((await call(a, "rateLimit", "task", "alice")).ok).toBe(false);
    expect(await call(b, "rateLimit", "task", "alice")).toEqual({ ok: true });
  });

  it("forgets a bucket once it has refilled, and keeps (and re-arms for) one that has not", async () => {
    const x = tenant();
    await drain(x, "task", "spent", 1);
    await drain(x, "task", "old", 1);
    const keys = () => runInDurableObject(x.stub, async (_i, s) => [...(await s.storage.list({ prefix: "rl:" })).keys()].sort());
    expect(await keys()).toEqual(["rl:task:old", "rl:task:spent"]);
    const full = Date.now() + 3_600_000;
    await runInDurableObject(x.stub, async (_i, s) => {
      await s.storage.put("rl:task:old", { tokens: 0, at: 0, full_at: Date.now() - 1 });
      await s.storage.put("rl:task:spent", { tokens: 0, at: 0, full_at: full });
      await s.storage.setAlarm(Date.now() + 10);
    });
    expect(await runDurableObjectAlarm(x.stub)).toBe(true);
    expect(await keys()).toEqual(["rl:task:spent"]);
    expect(await runInDurableObject(x.stub, (_i, s) => s.storage.getAlarm())).toBe(full);
  });

  it("at the cap a caller with no bucket is refused, one with a bucket is served, and a freed slot is reusable", async () => {
    const x = tenant();
    await drain(x, "task", "known", 1);
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
    expect(await call(x, "rateLimit", "task", "new")).toEqual({ ok: false, retry_after_ms: BUCKET_FULL_RETRY_MS });
    expect(await call(x, "rateLimit", "task", "known")).toEqual({ ok: true });
    await runInDurableObject(x.stub, (_i, s) => s.storage.delete("rl:find:filler0"));
    expect(await call(x, "rateLimit", "task", "new")).toEqual({ ok: true });
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

describe("limits on the directory", () => {
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
});
