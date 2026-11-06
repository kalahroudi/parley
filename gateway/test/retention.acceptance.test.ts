// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T307 acceptance: retention deletion at acknowledgment and at TTL, through the whole gateway (the admin sets
// the mode over HTTP, tasks run over /a2a, results travel over the tunnel) and checked in the storage itself.
// The unit suites (task.test.ts, device.test.ts, a2a.test.ts) prove each part; this one follows sealed bytes
// carrying a canary through every Durable Object the gateway has (Task, both Device DOs, Tenant) and asserts
// when they are there and that they are gone, in every way a held result can end:
//   acknowledged (one at a time, all at once, by `ack`, by a later hello's last_rx), expired at the TTL
//   (at the boundary and a day later, for any TTL the admin may choose, with no caller ever returning), canceled,
//   and failed by expiry. Strict never has them at all, and neither mode ever holds what the caller sent.
// Encrypted FILES in R2 are not held by the gateway yet: tests/pending-t307.test.mjs keeps that named.

import { SELF, env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SEALED_MEDIA_TYPE } from "../src/a2a";
import type { SignedKind } from "../src/parts";
import { QUEUE_TTL_DEFAULT_MS, QUEUE_TTL_MAX_MS, QUEUE_TTL_MIN_MS, TASK_TTL_DEFAULT_MS } from "../src/task";
import { b64, encodeWire, gw, header, taskBytes, taskHex } from "./wire";

afterEach(() => vi.useRealTimers());

let n = 0;
const ROLE: Record<string, string> = { TASK: "ROLE_USER", REPLY: "ROLE_USER", CANCEL: "ROLE_USER" };
const canary = (k: string) => new TextEncoder().encode(`CANARY-${k}-7e3a`);

// A tenant with devices "alice" (the caller) and "bob" (the target), the admin's session, and the plumbing.
function world() {
  const T = `ret${++n}`;
  const bearer = (d: string) => ({ Authorization: `Bearer dev:${T}:${d}` });
  const tenantStub = env.TENANT.get(env.TENANT.idFromName(T));
  const admin = tenantStub.createSession("admin@example.test", "admin").then((s) => `Bearer ps_${T}.${s.secret}`);
  const setRetention = async (body: unknown) => {
    const r = await SELF.fetch("https://gw/v1/admin/retention/put", { method: "POST", headers: { Authorization: await admin }, body: JSON.stringify(body) });
    expect(r.status).toBe(200);
  };
  const rpc = async (device: string, method: string, params: unknown) => {
    const r = await gw("https://gw/a2a", { method: "POST", headers: bearer(device), body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    expect(r.status).toBe(200);
    return (await r.json()) as any;
  };
  // A sealed message whose ciphertext starts with a canary naming it.
  const send = (kind: SignedKind, from: string, to: string, seq: number, id: string, tag = `${kind}${seq}`) =>
    rpc(from, "SendMessage", {
      message: {
        messageId: `m${++n}`,
        role: ROLE[kind] ?? "ROLE_AGENT",
        parts: [{ raw: b64(encodeWire({ header: header(kind, { tenant: T, sender: from, target: to, task: taskBytes(id), seq, context: "CANARY-NAME-7e3a.txt" }), bucket: 4096, ct: canary(tag) })), mediaType: SEALED_MEDIA_TYPE }],
      },
    });
  const taskStub = (id: string) => env.TASK.get(env.TASK.idFromName(`${T}:${taskHex(id)}`));
  const dump = async (...tasks: string[]) => {
    const stubs = [...tasks.map(taskStub), env.DEVICE.get(env.DEVICE.idFromName(`${T}:alice`)), env.DEVICE.get(env.DEVICE.idFromName(`${T}:bob`)), tenantStub];
    const out: Record<string, unknown>[] = [];
    for (const st of stubs) out.push(await runInDurableObject(st, async (_, ctx) => Object.fromEntries(await ctx.storage.list())));
    return JSON.stringify(out);
  };
  // Is the sealed message with this tag anywhere in the gateway's storage? Sealed parts travel as base64 inside JSON, at
  // whatever offset, so the scan decodes every long base64 run it finds and looks for the canary bytes in the result.
  const find = async (want: string, tasks: string[]) => {
    for (const run of (await dump(...tasks)).match(/[A-Za-z0-9+/]{200,}={0,2}/g) ?? []) {
      let bin: string;
      try {
        bin = atob(run.length % 4 ? run + "=".repeat(4 - (run.length % 4)) : run);
      } catch {
        continue;
      }
      if (bin.includes(want)) return true;
    }
    return false;
  };
  const holds = (tag: string, ...tasks: string[]) => find(new TextDecoder().decode(canary(tag)), tasks);
  const held = (id: string) => runInDurableObject(taskStub(id), async (_, ctx) => [...(await ctx.storage.list({ prefix: "q:" })).keys()]);
  const state = async (id: string) => (await rpc("alice", "GetTask", { id: taskHex(id) })).result;
  return { T, bearer, setRetention, rpc, send, dump, find, holds, held, state, taskStub };
}

// A tunnel the test reads events from and acknowledges by hand.
async function tunnel(T: string, device: string, session?: string, lastRx = 0) {
  const res = await gw("https://gw/v1/connect", { headers: { Upgrade: "websocket", Authorization: `Bearer dev:${T}:${device}` } });
  const ws = res.webSocket!;
  ws.accept();
  const inbox: any[] = [];
  const waiters: ((m: any) => void)[] = [];
  ws.addEventListener("message", (e) => {
    const m = JSON.parse(e.data as string);
    const w = waiters.shift();
    if (w) w(m);
    else inbox.push(m);
  });
  const next = () => (inbox.length ? Promise.resolve(inbox.shift()) : new Promise<any>((r) => waiters.push(r)));
  ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: lastRx, ...(session ? { session } : {}) }));
  const welcome = await next();
  expect(welcome.t).toBe("welcome");
  return {
    ws,
    session: welcome.session as string,
    event: async () => {
      const m = await next();
      expect(m.t).toBe("event");
      return { seq: m.seq as number, ...JSON.parse(m.body) };
    },
    quiet: () => inbox.length === 0,
    ack: (seq: number) => ws.send(JSON.stringify({ t: "ack", seq })),
  };
}
const gone = async (T: string, device: string) => {
  for (let i = 0; i < 200; i++) {
    if (!(await (env.DEVICE.get(env.DEVICE.idFromName(`${T}:${device}`)) as any).status()).connected) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("the tunnel did not close");
};
const until = async (f: () => Promise<boolean>) => {
  for (let i = 0; i < 300; i++) {
    if (await f()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("timed out");
};

// alice sends a task to bob and goes offline; bob is connected.
async function offlineCaller(w: ReturnType<typeof world>, id = "tk") {
  const alice = await tunnel(w.T, "alice");
  await tunnel(w.T, "bob");
  expect((await w.send("TASK", "alice", "bob", 0, id, `TASK-${id}`)).result).toBeDefined();
  alice.ws.close(1000, "bye");
  await gone(w.T, "alice");
}
const TAGS = ["STATUS1", "STATUS2", "RESULT3"];
// bob reports twice and finishes while alice is away.
async function bobReports(w: ReturnType<typeof world>, id = "tk") {
  expect((await w.send("STATUS", "bob", "alice", 1, id)).result.task.status.state).toBe("TASK_STATE_WORKING");
  expect((await w.send("STATUS", "bob", "alice", 2, id)).result.task.status.state).toBe("TASK_STATE_WORKING");
  expect((await w.send("RESULT", "bob", "alice", 3, id)).result.task.status.state).toBe("TASK_STATE_COMPLETED");
}
const everyHeld = (w: ReturnType<typeof world>, id = "tk") => Promise.all(TAGS.map((t) => w.holds(t, id)));

describe("Queued: deletion at acknowledgment", () => {
  it("holds sealed results while the caller is away, delivers them in order, and deletes each as it is acknowledged", async () => {
    const w = world();
    await w.setRetention({ mode: "queued" });
    await offlineCaller(w);
    await bobReports(w);
    // Control: the scan sees held bytes (so "gone" below means gone), and the gateway holds exactly the three results.
    expect(await everyHeld(w)).toEqual([true, true, true]);
    expect(await w.held("tk")).toHaveLength(3);
    // What the caller sent was relayed and never kept.
    expect(await w.holds("TASK-tk", "tk")).toBe(false);

    const alice = await tunnel(w.T, "alice");
    const got = [await alice.event(), await alice.event(), await alice.event()];
    expect(got.map((e) => e.task.status.message.metadata.parley.seq)).toEqual([1, 2, 3]);
    expect(got.map((e) => e.seq)).toEqual([1, 2, 3]);
    expect(await everyHeld(w)).toEqual([true, true, true]); // delivered is not acknowledged
    expect((await w.state("tk")).metadata.parley.ciphertext_deleted_at).toBeUndefined();

    alice.ack(1);
    await until(async () => (await w.held("tk")).length === 2);
    expect(await everyHeld(w)).toEqual([false, true, true]);
    alice.ack(2);
    await until(async () => (await w.held("tk")).length === 1);
    expect(await everyHeld(w)).toEqual([false, false, true]);
    expect((await w.state("tk")).metadata.parley.ciphertext_deleted_at).toBeUndefined(); // one is left
    alice.ack(3);
    await until(async () => (await w.held("tk")).length === 0);
    expect(await everyHeld(w)).toEqual([false, false, false]);
    const t = await w.state("tk");
    expect(t.status.state).toBe("TASK_STATE_COMPLETED");
    expect(t.metadata.parley.ciphertext_deleted_at).toBeGreaterThan(0);
    // Nothing readable was ever there, in clear or inside any base64 part (the canary names a file in the signed header).
    expect(await w.dump("tk")).not.toContain("CANARY-NAME");
    expect(await w.find("CANARY-NAME", ["tk"])).toBe(false);
  });

  it("one acknowledgment of the last sequence number deletes everything before it, across tasks", async () => {
    const w = world();
    await w.setRetention({ mode: "queued" });
    await offlineCaller(w, "t1");
    const alice0 = await tunnel(w.T, "alice");
    await w.send("TASK", "alice", "bob", 0, "t2", "TASK-t2");
    alice0.ws.close(1000, "bye");
    await gone(w.T, "alice");
    await w.send("RESULT", "bob", "alice", 1, "t1", "R-t1");
    await w.send("RESULT", "bob", "alice", 1, "t2", "R-t2");
    expect([await w.holds("R-t1", "t1", "t2"), await w.holds("R-t2", "t1", "t2")]).toEqual([true, true]);
    const alice = await tunnel(w.T, "alice");
    const a = await alice.event();
    const b = await alice.event();
    alice.ack(Math.max(a.seq, b.seq));
    await until(async () => !(await w.holds("R-t1", "t1", "t2")) && !(await w.holds("R-t2", "t1", "t2")));
    expect([(await w.state("t1")).metadata.parley.ciphertext_deleted_at, (await w.state("t2")).metadata.parley.ciphertext_deleted_at].map((x) => x > 0)).toEqual([true, true]);
  });

  it("a hello that reports what the daemon already received deletes it too, with no ack frame", async () => {
    const w = world();
    await w.setRetention({ mode: "queued" });
    await offlineCaller(w);
    await bobReports(w);
    const first = await tunnel(w.T, "alice");
    await first.event();
    await first.event();
    await first.event();
    first.ws.close(1000, "bye"); // dropped without acknowledging anything
    await gone(w.T, "alice");
    expect(await everyHeld(w)).toEqual([true, true, true]);
    const second = await tunnel(w.T, "alice", first.session, 3); // "I have seen up to 3"
    await until(async () => (await w.held("tk")).length === 0);
    expect(await everyHeld(w)).toEqual([false, false, false]);
    expect(second.quiet()).toBe(true); // nothing is sent again
  });

  it("an unacknowledged event is delivered again after a reconnect, and stays held until it is acknowledged", async () => {
    const w = world();
    await w.setRetention({ mode: "queued" });
    await offlineCaller(w);
    await w.send("RESULT", "bob", "alice", 1, "tk");
    const first = await tunnel(w.T, "alice");
    await first.event();
    first.ws.close(1000, "bye");
    await gone(w.T, "alice");
    const second = await tunnel(w.T, "alice", first.session, 0);
    expect((await second.event()).task.status.message.metadata.parley.seq).toBe(1);
    expect(await w.holds("RESULT1", "tk")).toBe(true);
    second.ack(2); // the resent copy carries a fresh tunnel sequence number
    await until(async () => !(await w.holds("RESULT1", "tk")));
  });

  it("an acknowledgment from the wrong device or for a sequence number never sent deletes nothing", async () => {
    const w = world();
    await w.setRetention({ mode: "queued" });
    await offlineCaller(w);
    await w.send("RESULT", "bob", "alice", 1, "tk");
    const bob = await tunnel(w.T, "bob"); // the target is another device: it holds nothing for this task
    bob.ack(0);
    bob.ws.close(1000, "bye");
    const alice = await tunnel(w.T, "alice");
    alice.ack(99); // beyond anything sent: the gateway closes the tunnel
    await new Promise((r) => setTimeout(r, 50));
    expect(await w.holds("RESULT1", "tk")).toBe(true);
  });
});

describe("Queued: deletion at the TTL", () => {
  // Moves the clock, runs the Task DO's alarm.
  const pastTtl = async (w: ReturnType<typeof world>, ms: number, id = "tk") => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + ms);
    return runDurableObjectAlarm(w.taskStub(id));
  };

  for (const ttl of [QUEUE_TTL_MIN_MS, QUEUE_TTL_DEFAULT_MS, QUEUE_TTL_MAX_MS]) {
    it(`a result nobody comes for is deleted at the tenant's TTL (${ttl / 60_000} min), and not a moment before`, async () => {
      const w = world();
      await w.setRetention({ mode: "queued", queue_ttl_ms: ttl });
      await offlineCaller(w);
      await w.send("RESULT", "bob", "alice", 1, "tk");
      expect(await w.holds("RESULT1", "tk")).toBe(true);
      // The deadline the Task DO stored for it: exactly the TTL after it was held.
      const exp = await runInDurableObject(w.taskStub("tk"), async (_, ctx) => [...(await ctx.storage.list<{ exp: number }>({ prefix: "q:" })).values()].map((q) => q.exp));
      expect(exp).toHaveLength(1);
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(exp[0]! - 1);
      await runDurableObjectAlarm(w.taskStub("tk")); // an alarm one millisecond early deletes nothing
      expect(await w.holds("RESULT1", "tk")).toBe(true);
      expect(await w.held("tk")).toHaveLength(1);
      vi.setSystemTime(exp[0]!);
      expect(await runDurableObjectAlarm(w.taskStub("tk"))).toBe(true);
      expect(await w.holds("RESULT1", "tk")).toBe(false);
      expect(await w.held("tk")).toEqual([]);
      vi.useRealTimers();
      // The caller who finally connects gets nothing, and the record says when the ciphertext went.
      const alice = await tunnel(w.T, "alice");
      expect(alice.quiet()).toBe(true);
      expect((await w.state("tk")).metadata.parley.ciphertext_deleted_at).toBeGreaterThan(0);
    });
  }

  it("a late reader gets nothing even before the alarm has run", async () => {
    const w = world();
    await w.setRetention({ mode: "queued", queue_ttl_ms: QUEUE_TTL_MIN_MS });
    await offlineCaller(w);
    await w.send("RESULT", "bob", "alice", 1, "tk");
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + QUEUE_TTL_MIN_MS + 1);
    const alice = await tunnel(w.T, "alice"); // connects after the TTL, before any alarm
    expect(alice.quiet()).toBe(true);
  });

  it("each result expires on its own clock: an earlier one goes while a later one is still held", async () => {
    const w = world();
    await w.setRetention({ mode: "queued", queue_ttl_ms: QUEUE_TTL_MIN_MS });
    await offlineCaller(w);
    await w.send("STATUS", "bob", "alice", 1, "tk");
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = Date.now();
    vi.setSystemTime(t0 + QUEUE_TTL_MIN_MS / 2);
    await w.send("RESULT", "bob", "alice", 2, "tk");
    vi.setSystemTime(t0 + QUEUE_TTL_MIN_MS);
    await runDurableObjectAlarm(w.taskStub("tk"));
    expect([await w.holds("STATUS1", "tk"), await w.holds("RESULT2", "tk")]).toEqual([false, true]);
    vi.setSystemTime(t0 + QUEUE_TTL_MIN_MS * 1.5);
    await runDurableObjectAlarm(w.taskStub("tk"));
    expect(await w.holds("RESULT2", "tk")).toBe(false);
  });

  it("a TTL change applies from the next held result, and the task keeps the mode it was created under", async () => {
    const w = world();
    await w.setRetention({ mode: "queued", queue_ttl_ms: QUEUE_TTL_MAX_MS });
    await offlineCaller(w);
    await w.setRetention({ mode: "queued", queue_ttl_ms: QUEUE_TTL_MIN_MS });
    await w.send("RESULT", "bob", "alice", 1, "tk");
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + QUEUE_TTL_MIN_MS);
    await runDurableObjectAlarm(w.taskStub("tk"));
    expect(await w.holds("RESULT1", "tk")).toBe(false); // the new, shorter TTL applied to what was held after it
  });

  it("the task expiring while a result is held deletes it, and a held result outlives neither cancel nor expiry", async () => {
    const w = world();
    await w.setRetention({ mode: "queued", queue_ttl_ms: QUEUE_TTL_MAX_MS });
    await offlineCaller(w);
    await w.send("STATUS", "bob", "alice", 1, "tk");
    expect(await w.holds("STATUS1", "tk")).toBe(true);
    expect(await pastTtl(w, TASK_TTL_DEFAULT_MS + 1)).toBe(true); // the task's own deadline comes first
    expect(await w.holds("STATUS1", "tk")).toBe(false);
    expect((await w.state("tk")).status.state).toBe("TASK_STATE_FAILED");
  });

  it("cancel deletes what is held at once", async () => {
    const w = world();
    await w.setRetention({ mode: "queued" });
    await offlineCaller(w);
    await w.send("STATUS", "bob", "alice", 1, "tk");
    expect(await w.holds("STATUS1", "tk")).toBe(true);
    const part = { raw: b64(encodeWire({ header: header("CANCEL", { tenant: w.T, sender: "alice", target: "bob", task: taskBytes("tk"), seq: 1 }), bucket: 4096 })), mediaType: SEALED_MEDIA_TYPE };
    const r = await w.rpc("alice", "CancelTask", { id: taskHex("tk"), metadata: { parley: { messageId: "c1", parts: [part] } } });
    expect(r.result.status.state).toBe("TASK_STATE_CANCELED");
    expect(await w.holds("STATUS1", "tk")).toBe(false);
    expect(await w.held("tk")).toEqual([]);
    expect(await tunnel(w.T, "alice").then((a) => a.quiet())).toBe(true);
  });
});

describe("Strict stores no result at all", () => {
  it("a caller that is away fails the task and nothing sealed is kept anywhere", async () => {
    const w = world();
    await w.setRetention({ mode: "strict" });
    await offlineCaller(w);
    const r = await w.send("STATUS", "bob", "alice", 1, "tk");
    expect(r.error?.code).toBe(-32010);
    expect((await w.state("tk")).status.state).toBe("TASK_STATE_FAILED");
    for (const tag of ["STATUS1", "TASK-tk"]) expect(await w.holds(tag, "tk"), tag).toBe(false);
    expect(await w.held("tk")).toEqual([]);
  });

  it("a connected caller gets results relayed, and still nothing sealed is kept, in either mode", async () => {
    for (const mode of ["strict", "queued"]) {
      const w = world();
      await w.setRetention({ mode });
      const alice = await tunnel(w.T, "alice");
      await tunnel(w.T, "bob");
      await w.send("TASK", "alice", "bob", 0, "tk", "TASK-live");
      await w.send("STATUS", "bob", "alice", 1, "tk");
      await w.send("RESULT", "bob", "alice", 2, "tk");
      expect((await alice.event()).task.status.message.metadata.parley.seq).toBe(1);
      expect((await alice.event()).task.status.message.metadata.parley.seq).toBe(2);
      for (const tag of ["TASK-live", "STATUS1", "RESULT2"]) expect(await w.holds(tag, "tk"), `${mode} ${tag}`).toBe(false);
    }
  });
});

describe("what the caller sends is never held, in either mode", () => {
  for (const mode of ["strict", "queued"]) {
    it(`${mode}: a reply to an absent target fails the task and keeps nothing`, async () => {
      const w = world();
      await w.setRetention({ mode });
      await tunnel(w.T, "alice");
      const bob = await tunnel(w.T, "bob");
      await w.send("TASK", "alice", "bob", 0, "tk", "TASK-x");
      await w.send("INPUT_REQUIRED", "bob", "alice", 1, "tk");
      bob.ws.close(1000, "bye");
      await gone(w.T, "bob");
      const r = await w.send("REPLY", "alice", "bob", 1, "tk", "REPLY-x");
      expect(r.error?.code).toBe(-32010);
      for (const tag of ["TASK-x", "REPLY-x"]) expect(await w.holds(tag, "tk"), tag).toBe(false);
    });
  }
});
