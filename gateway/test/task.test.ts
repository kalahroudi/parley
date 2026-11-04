// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Tier 1 (plan.md coverage policy): the task state machine, deadlines and
// retention logic. src/task.ts is held to 100% of lines, branches and functions
// (vitest.config.ts) and to mutation testing (scripts/mutation-ts.mjs).

import { env, evictDurableObject, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_QUEUED, MAX_QUEUED_BYTES, NEXT, QUEUE_TTL_DEFAULT_MS, QUEUE_TTL_MAX_MS, QUEUE_TTL_MIN_MS, TASK_METADATA_RETENTION_MS, TASK_TTL_DEFAULT_MS, TASK_TTL_MAX_MS, TERMINAL, type Task, type TaskEvent, type TaskRecord, type TaskState } from "../src/task";

type Stub = DurableObjectStub<Task>;
const T = "t1";
let n = 0;
const stub = () => env.TASK.get(env.TASK.idFromName(`${T}:task${++n}`)) as Stub;
const fresh = async (ttl_ms?: number) => {
  const s = stub();
  expect(typeof (await s.create({ tenant: T, id: "abc", caller: "alice", target: "bob", ttl_ms }))).toBe("object");
  return s;
};
const asTarget = (s: Stub, e: TaskEvent, seq: number) => s.apply(T, "bob", e, seq);
const asCaller = (s: Stub, e: TaskEvent, seq: number) => s.apply(T, "alice", e, seq);
const rec = async (s: Stub) => (await s.get(T)) as TaskRecord;
const state = async (s: Stub) => (await rec(s)).state;
const alarmOf = (s: Stub) => runInDurableObject(s, (_, ctx) => ctx.storage.getAlarm());
const deliverAlarm = (s: Stub) => runInDurableObject<Task, void>(s, (o) => o.alarm());
const stored = (s: Stub) => runInDurableObject(s, async (_, ctx) => Object.fromEntries(await ctx.storage.list()));

afterEach(() => vi.useRealTimers());

it("the lifetimes are 15 minutes by default, 24 hours at most, and metadata is kept 90 days", () => {
  expect(TASK_TTL_DEFAULT_MS).toBe(900_000);
  expect(TASK_TTL_MAX_MS).toBe(86_400_000);
  expect(TASK_METADATA_RETENTION_MS).toBe(7_776_000_000);
});

describe("create", () => {
  it("starts SUBMITTED with the default expiry and metadata only", async () => {
    const t0 = Date.now();
    const s = stub();
    const r = (await s.create({ tenant: T, id: "abc", caller: "alice", target: "bob" })) as TaskRecord;
    expect(r).toMatchObject({ id: "abc", tenant: T, state: "SUBMITTED", caller_seq: 0, target_seq: 0, caller: "alice", target: "bob" });
    expect(r.expires_at - r.created).toBe(TASK_TTL_DEFAULT_MS);
    expect(r.created).toBeGreaterThanOrEqual(t0);
    expect(Object.keys(r).sort()).toEqual(["caller", "caller_seq", "created", "expires_at", "id", "qseq", "retention", "state", "target", "target_seq", "tenant", "updated"]);
    expect(await rec(s)).toEqual(r);
    expect(await alarmOf(s)).toBe(r.expires_at);
  });

  it("rejects bad input and a second create, and stores nothing for them", async () => {
    const s = stub();
    const ok = { tenant: T, id: "abc", caller: "alice", target: "bob" };
    const bad: Record<string, unknown>[] = [
      { retention: "lazy" }, { retention: 1 },
      { id: "a/b" }, { tenant: "t:1" }, { caller: "" }, { target: "x".repeat(65) }, { id: 5 }, { tenant: undefined },
      { target: "alice" }, // one device in both roles
      { ttl_ms: 0 }, { ttl_ms: -1 }, { ttl_ms: NaN }, { ttl_ms: 1.5 }, { ttl_ms: "5" }, { ttl_ms: TASK_TTL_MAX_MS + 1 },
    ];
    for (const b of bad) expect(await s.create({ ...ok, ...b } as typeof ok), JSON.stringify(b)).toBe("bad_request");
    expect(await s.get(T)).toBeNull();
    expect(await stored(s)).toEqual({});
    expect(await alarmOf(s)).toBeNull();
    expect(typeof (await s.create({ ...ok, ttl_ms: TASK_TTL_MAX_MS }))).toBe("object");
    expect(await s.create(ok)).toBe("exists");
    expect((await rec(s)).expires_at - (await rec(s)).created).toBe(TASK_TTL_MAX_MS);
  });

  it("accepts the smallest ttl", async () => {
    const s = stub();
    expect(await s.create({ tenant: T, id: "abc", caller: "alice", target: "bob", ttl_ms: 1 })).toMatchObject({ state: "SUBMITTED" });
  });
});

// Every state x every event, by every party: the table below is the whole
// machine. Anything not listed is refused, and a refusal changes nothing.
describe("state machine, exhaustive", () => {
  const states: TaskState[] = ["SUBMITTED", "WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "CANCELED", "REJECTED"];
  const events: TaskEvent[] = ["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "REJECTED", "CANCEL", "REPLY"];
  const callerEvents = new Set<TaskEvent>(["CANCEL", "REPLY"]);
  // Path from SUBMITTED to each state; returns the last sequence each side used.
  const reach: Record<TaskState, (s: Stub) => Promise<{ c: number; t: number }>> = {
    SUBMITTED: async () => ({ c: 0, t: 0 }),
    WORKING: async (s) => (await asTarget(s, "WORKING", 1), { c: 0, t: 1 }),
    INPUT_REQUIRED: async (s) => (await asTarget(s, "INPUT_REQUIRED", 1), { c: 0, t: 1 }),
    COMPLETED: async (s) => (await asTarget(s, "COMPLETED", 1), { c: 0, t: 1 }),
    FAILED: async (s) => (await asTarget(s, "FAILED", 1), { c: 0, t: 1 }),
    CANCELED: async (s) => (await asCaller(s, "CANCEL", 1), { c: 1, t: 0 }),
    REJECTED: async (s) => (await asTarget(s, "REJECTED", 1), { c: 0, t: 1 }),
  };
  const dest = (from: TaskState, e: TaskEvent): TaskState | null => {
    const to: TaskState = e === "CANCEL" ? "CANCELED" : e === "REPLY" ? "WORKING" : e;
    if (e === "REPLY" && from !== "INPUT_REQUIRED") return null;
    return NEXT[from].includes(to) ? to : null;
  };

  it("the table is the documented one", () => {
    expect(NEXT).toEqual({
      SUBMITTED: ["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "CANCELED", "REJECTED"],
      WORKING: ["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "CANCELED"],
      INPUT_REQUIRED: ["WORKING", "COMPLETED", "FAILED", "CANCELED"],
      COMPLETED: [], FAILED: [], CANCELED: [], REJECTED: [],
    });
    for (const st of states) expect(TERMINAL.has(st)).toBe(NEXT[st].length === 0);
  });

  for (const from of states) {
    for (const ev of events) {
      const owner = callerEvents.has(ev) ? "alice" : "bob";
      const stranger = callerEvents.has(ev) ? "bob" : "alice";
      it(`${from} + ${ev}`, async () => {
        const to = dest(from, ev);
        const s = await fresh();
        const { c, t } = await reach[from](s);
        expect(await state(s)).toBe(from);
        const before = await rec(s);
        // The wrong party and an outsider are forbidden whatever the state, with no change.
        expect(await s.apply(T, stranger, ev, 99)).toBe("forbidden");
        expect(await s.apply(T, "mallory", ev, 99)).toBe("forbidden");
        expect(await rec(s)).toEqual(before);
        const seq = (owner === "alice" ? c : t) + 1;
        const r = await s.apply(T, owner, ev, seq);
        if (to) {
          expect(r).toMatchObject({ state: to, [owner === "alice" ? "caller_seq" : "target_seq"]: seq });
          expect(TERMINAL.has(to) ? (r as TaskRecord).reason : "none").toBe(TERMINAL.has(to) ? (ev === "CANCEL" ? "canceled" : "target") : "none");
        } else {
          expect(r).toBe(TERMINAL.has(from) ? "terminal" : "bad_transition");
          expect(await rec(s)).toEqual(before); // refused: no state, sequence, timestamp or reason change
        }
      });
    }
  }

  it("terminal states are absorbing: nothing moves them, whoever asks and whatever the sequence", async () => {
    for (const from of ["COMPLETED", "FAILED", "CANCELED", "REJECTED"] as const) {
      const s = await fresh();
      await reach[from](s);
      const before = await rec(s);
      for (const ev of events) {
        for (const dev of ["alice", "bob"]) expect(["terminal", "forbidden"]).toContain(await s.apply(T, dev, ev, 1000));
      }
      expect(await s.callerDisconnected(T, "alice")).toEqual(before);
      expect(await rec(s)).toEqual(before);
    }
  });

  it("an unknown event is refused", async () => {
    const s = await fresh();
    for (const dev of ["alice", "bob"]) expect(await s.apply(T, dev, "BOGUS" as TaskEvent, 1)).toBe("forbidden");
    expect(await state(s)).toBe("SUBMITTED");
  });

  it("a live move records no reason", async () => {
    const s = await fresh();
    for (const e of ["WORKING", "INPUT_REQUIRED"] as const) {
      await asTarget(s, e, e === "WORKING" ? 1 : 2);
      expect(Object.keys((await stored(s)).task as object)).not.toContain("reason");
    }
    await asCaller(s, "REPLY", 1);
    expect(Object.keys((await stored(s)).task as object)).not.toContain("reason");
  });

  it("a move returns only after both its record and its alarm are written", async () => {
    for (const slow of ["put", "setAlarm"] as const) {
      const s = await fresh();
      let written = false;
      await runInDurableObject<Task, void>(s, async (o, ctx) => {
        const store = ctx.storage as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
        const real = store[slow]!.bind(ctx.storage);
        store[slow] = async (...a) => {
          await new Promise((r) => setTimeout(r, 20));
          written = true;
          return real(...a);
        };
        await o.apply(T, "bob", "WORKING", 1);
        expect(written, slow).toBe(true);
        store[slow] = real;
      });
    }
  });

  it("runs the full question and answer lifecycle", async () => {
    const s = await fresh();
    await asTarget(s, "WORKING", 1);
    await asTarget(s, "WORKING", 2); // progress update
    await asTarget(s, "INPUT_REQUIRED", 3);
    await asCaller(s, "REPLY", 1);
    await asTarget(s, "INPUT_REQUIRED", 4);
    await asCaller(s, "REPLY", 2);
    expect(await asTarget(s, "COMPLETED", 5)).toMatchObject({ state: "COMPLETED", reason: "target", caller_seq: 2, target_seq: 5 });
  });
});

describe("sequence numbers", () => {
  it("must strictly increase per sender, and a refusal changes nothing", async () => {
    const s = await fresh();
    await asTarget(s, "WORKING", 5);
    const before = await rec(s);
    for (const seq of [5, 4, 0, -1, 1.5, NaN, Infinity, 2 ** 60]) {
      expect(await asTarget(s, "INPUT_REQUIRED", seq), String(seq)).toBe("bad_seq");
      expect(await asCaller(s, "CANCEL", seq <= 0 ? seq : NaN), String(seq)).toBe("bad_seq");
    }
    expect(await rec(s)).toEqual(before);
    expect(await asTarget(s, "INPUT_REQUIRED", 7)).toMatchObject({ target_seq: 7 });
  });

  it("are counted per sender: the caller's first message is not refused for the target's count", async () => {
    const s = await fresh();
    await asTarget(s, "WORKING", 1);
    await asTarget(s, "WORKING", 2);
    await asTarget(s, "INPUT_REQUIRED", 3);
    expect(await asCaller(s, "REPLY", 1)).toMatchObject({ state: "WORKING", caller_seq: 1, target_seq: 3 });
    expect(await asCaller(s, "CANCEL", 2)).toMatchObject({ state: "CANCELED", caller_seq: 2, target_seq: 3 });
  });

  it("a replayed hint is refused after the state moved on", async () => {
    const s = await fresh();
    await asTarget(s, "INPUT_REQUIRED", 1);
    await asCaller(s, "REPLY", 1);
    await asTarget(s, "INPUT_REQUIRED", 2);
    expect(await asCaller(s, "REPLY", 1)).toBe("bad_seq"); // would otherwise answer the second question
    expect(await state(s)).toBe("INPUT_REQUIRED");
  });
});

describe("cancel", () => {
  it("is authorized for the task's caller only", async () => {
    const s = await fresh();
    await asTarget(s, "WORKING", 1);
    for (const dev of ["bob", "mallory", "ALICE", ""]) expect(await s.apply(T, dev, "CANCEL", 1)).toBe("forbidden");
    expect(await s.apply("other", "alice", "CANCEL", 1)).toBe("not_found");
    expect(await state(s)).toBe("WORKING");
    expect(await asCaller(s, "CANCEL", 1)).toMatchObject({ state: "CANCELED", reason: "canceled" });
  });

  it("makes a late reply impossible, also after the object restarts", async () => {
    const s = await fresh();
    await asTarget(s, "INPUT_REQUIRED", 1);
    expect(await asCaller(s, "CANCEL", 1)).toMatchObject({ state: "CANCELED", reason: "canceled" });
    const check = async () => {
      for (const e of ["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "REJECTED"] as const) expect(await asTarget(s, e, 2)).toBe("terminal");
      expect(await asCaller(s, "REPLY", 2)).toBe("terminal");
      expect(await asCaller(s, "CANCEL", 2)).toBe("terminal");
      expect(await state(s)).toBe("CANCELED");
    };
    await check();
    await evictDurableObject(s);
    await check();
  });

  it("a second cancel is refused and leaves the first one's record alone", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const s = await fresh();
    await asCaller(s, "CANCEL", 1);
    const first = await rec(s);
    vi.setSystemTime(Date.now() + 5000);
    expect(await asCaller(s, "CANCEL", 2)).toBe("terminal");
    expect(await asCaller(s, "CANCEL", 1)).toBe("terminal");
    expect(await rec(s)).toEqual(first);
  });

  it("cancel then complete, and complete then cancel: the first one wins, either order", async () => {
    const a = await fresh();
    expect(await asCaller(a, "CANCEL", 1)).toMatchObject({ state: "CANCELED" });
    expect(await asTarget(a, "COMPLETED", 1)).toBe("terminal");
    const b = await fresh();
    expect(await asTarget(b, "COMPLETED", 1)).toMatchObject({ state: "COMPLETED" });
    expect(await asCaller(b, "CANCEL", 1)).toBe("terminal");
    expect(await state(a)).toBe("CANCELED");
    expect(await state(b)).toBe("COMPLETED");
  });

  it("cancel against the deadline: the instant of expiry belongs to expiry", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const s = await fresh(1000);
    const t0 = (await rec(s)).created;
    vi.setSystemTime(t0 + 999);
    expect(await asCaller(s, "CANCEL", 1)).toMatchObject({ state: "CANCELED" });
    const late = await fresh(1000);
    vi.setSystemTime(Date.now() + 1000);
    expect(await asCaller(late, "CANCEL", 1)).toBe("terminal");
    expect(await rec(late)).toMatchObject({ state: "FAILED", reason: "expired" });
  });

  it("racing cancel, complete and fail: exactly one terminal move, and the record agrees with it", async () => {
    for (let i = 0; i < 10; i++) {
      const s = await fresh();
      await asTarget(s, "WORKING", 1);
      const calls = [asCaller(s, "CANCEL", 1), asTarget(s, "COMPLETED", 2), asTarget(s, "FAILED", 3), asCaller(s, "CANCEL", 2), asTarget(s, "REJECTED", 4)];
      const results = await Promise.all(calls);
      const won = results.filter((r): r is TaskRecord => typeof r === "object");
      expect(won).toHaveLength(1);
      expect(results.filter((r) => typeof r === "string").every((r) => r === "terminal" || r === "bad_transition")).toBe(true);
      expect(await state(s)).toBe(won[0]!.state);
    }
  });

  it("interleaved requests cannot corrupt the record", async () => {
    const s = await fresh();
    await asTarget(s, "INPUT_REQUIRED", 1);
    const results = await Promise.all([
      asCaller(s, "REPLY", 1), asCaller(s, "REPLY", 1), asTarget(s, "WORKING", 2), asTarget(s, "WORKING", 2),
      asTarget(s, "INPUT_REQUIRED", 3), s.get(T), asCaller(s, "CANCEL", 2), s.callerDisconnected(T, "alice"),
    ]);
    const final = await rec(s);
    expect(final.caller_seq).toBeLessThanOrEqual(2);
    expect(TERMINAL.has(final.state)).toBe(true); // the cancel and the disconnect both end it
    expect(results.filter((r) => r === "bad_seq").length).toBeGreaterThanOrEqual(2); // each duplicate lost
    expect(await asCaller(s, "CANCEL", 9)).toBe("terminal");
  });
});

describe("authorization and isolation", () => {
  it("answers not_found for another tenant, and reveals and changes nothing", async () => {
    const s = await fresh();
    await asTarget(s, "WORKING", 1);
    const before = await rec(s);
    expect(await s.apply("t2", "alice", "CANCEL", 1)).toBe("not_found");
    expect(await s.apply("t2", "bob", "COMPLETED", 2)).toBe("not_found");
    expect(await s.callerDisconnected("t2", "alice")).toBe("not_found");
    expect(await s.get("t2")).toBeNull();
    expect(await s.get("")).toBeNull();
    expect(await rec(s)).toEqual(before);
  });

  it("takes the role from the device, not from the request", async () => {
    const s = await fresh();
    expect(await s.apply(T, "mallory", "WORKING", 1)).toBe("forbidden");
    expect(await s.apply(T, "alice", "COMPLETED", 1)).toBe("forbidden"); // the caller cannot complete its own task
    expect(await s.apply(T, "bob", "CANCEL", 1)).toBe("forbidden");
    expect(await s.apply(T, "bob", "REPLY", 1)).toBe("forbidden");
    expect(await state(s)).toBe("SUBMITTED");
  });

  it("reports an unknown task", async () => {
    const s = stub();
    expect(await asCaller(s, "CANCEL", 1)).toBe("not_found");
    expect(await s.callerDisconnected(T, "alice")).toBe("not_found");
    expect(await s.get(T)).toBeNull();
  });

  it("only the caller's disconnect fails a task", async () => {
    const s = await fresh();
    expect(await s.callerDisconnected(T, "bob")).toBe("forbidden");
    expect(await s.callerDisconnected(T, "mallory")).toBe("forbidden");
    expect(await state(s)).toBe("SUBMITTED");
    expect(await s.callerDisconnected(T, "alice")).toMatchObject({ state: "FAILED", reason: "disconnected" });
    expect(await asTarget(s, "COMPLETED", 1)).toBe("terminal");
    const done = await fresh();
    await asTarget(done, "COMPLETED", 1);
    const before = await rec(done);
    expect(await done.callerDisconnected(T, "alice")).toEqual(before);
    expect(await rec(done)).toEqual(before);
  });
});

describe("metadata only", () => {
  const CANARY = "CANARY-7f3a9c-payload";

  it("stores ids, states, counters and timestamps; extra fields, content and keys never land in storage", async () => {
    const s = stub();
    const hostile = { tenant: T, id: "abc", caller: "alice", target: "bob", payload: CANARY, ciphertext: CANARY, key: CANARY, ttl_ms: 60_000 };
    await s.create(hostile);
    await (s.apply as (...a: unknown[]) => Promise<unknown>)(T, "bob", "INPUT_REQUIRED", 1, CANARY, { body: CANARY });
    await (s.apply as (...a: unknown[]) => Promise<unknown>)(T, "alice", "REPLY", 1, CANARY);
    await asTarget(s, "COMPLETED", 2);
    const all = await stored(s);
    expect(Object.keys(all)).toEqual(["task"]); // one key, no side tables
    expect(JSON.stringify(all)).not.toContain(CANARY);
    const r = all.task as Record<string, unknown>;
    expect(Object.keys(r).sort()).toEqual(["caller", "caller_seq", "created", "expires_at", "id", "qseq", "reason", "retention", "state", "target", "target_seq", "tenant", "updated"]);
    for (const v of Object.values(r)) expect(["string", "number"]).toContain(typeof v);
  });

  it("leaves no storage and no alarm once finished tasks are purged", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const s = await fresh();
    await asCaller(s, "CANCEL", 1);
    expect(await alarmOf(s)).toBe((await rec(s)).updated + TASK_METADATA_RETENTION_MS);
    vi.setSystemTime(Date.now() + TASK_METADATA_RETENTION_MS);
    expect(await runDurableObjectAlarm(s)).toBe(true);
    expect(await stored(s)).toEqual({});
    expect(await alarmOf(s)).toBeNull();
    expect(await s.get(T)).toBeNull();
    // The id is free again.
    expect(typeof (await s.create({ tenant: T, id: "abc", caller: "alice", target: "bob" }))).toBe("object");
  });
});

describe("deadlines, alarms and restarts", () => {
  beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));

  it("fails a live task at its deadline, on read, without the alarm; the instant itself is expired", async () => {
    const s = await fresh(1000);
    const exp = (await rec(s)).expires_at;
    await asTarget(s, "WORKING", 1);
    vi.setSystemTime(exp - 1);
    expect(await state(s)).toBe("WORKING");
    vi.setSystemTime(exp);
    expect(await s.get(T)).toMatchObject({ state: "FAILED", reason: "expired" });
  });

  it("stamps the expiry at the deadline, whenever it is noticed", async () => {
    const lazy = await fresh(1000);
    const exp = (await rec(lazy)).expires_at;
    vi.setSystemTime(exp + 7_000_000);
    expect((await rec(lazy)).updated).toBe(exp);
    expect(await alarmOf(lazy)).toBe(exp + TASK_METADATA_RETENTION_MS);
  });

  it("refuses updates after the deadline", async () => {
    const s = await fresh(1000);
    vi.setSystemTime(Date.now() + 1000);
    expect(await asTarget(s, "COMPLETED", 1)).toBe("terminal");
    expect(await asCaller(s, "CANCEL", 1)).toBe("terminal");
    expect(await s.callerDisconnected(T, "alice")).toMatchObject({ state: "FAILED", reason: "expired" });
    expect((await rec(s)).reason).toBe("expired");
  });

  it("the alarm expires the task and arms the metadata purge; a second delivery changes nothing", async () => {
    const s = await fresh(1000);
    const exp = (await rec(s)).expires_at;
    expect(await alarmOf(s)).toBe(exp);
    vi.setSystemTime(exp + 1);
    expect(await runDurableObjectAlarm(s)).toBe(true);
    const after = await rec(s);
    expect(after).toMatchObject({ state: "FAILED", reason: "expired", updated: exp });
    expect(await alarmOf(s)).toBe(exp + TASK_METADATA_RETENTION_MS);
    await deliverAlarm(s); // re-delivered
    await deliverAlarm(s);
    expect(await rec(s)).toEqual(after);
    expect(await alarmOf(s)).toBe(exp + TASK_METADATA_RETENTION_MS);
  });

  it("an alarm that fires before the deadline keeps the expiry alarm armed", async () => {
    const s = await fresh(1000);
    const exp = (await rec(s)).expires_at;
    await runInDurableObject<Task, void>(s, async (o, ctx) => {
      await ctx.storage.deleteAlarm();
      await o.alarm();
      expect(await ctx.storage.getAlarm()).toBe(exp);
    });
    expect(await state(s)).toBe("SUBMITTED");
  });

  it("every live move keeps the expiry alarm; every terminal move arms the purge", async () => {
    const s = await fresh(10_000);
    const exp = (await rec(s)).expires_at;
    await asTarget(s, "WORKING", 1);
    expect(await alarmOf(s)).toBe(exp);
    vi.setSystemTime(Date.now() + 100);
    const r = (await asTarget(s, "COMPLETED", 2)) as TaskRecord;
    expect(await alarmOf(s)).toBe(r.updated + TASK_METADATA_RETENTION_MS);
  });

  it("the alarm after retention deletes the record; before it, the purge is re-armed", async () => {
    const s = await fresh(1000);
    await asTarget(s, "REJECTED", 1);
    const done = (await rec(s)).updated;
    vi.setSystemTime(done + TASK_METADATA_RETENTION_MS - 1);
    expect(await runDurableObjectAlarm(s)).toBe(true); // not yet due
    expect(await s.get(T)).not.toBeNull();
    expect(await alarmOf(s)).toBe(done + TASK_METADATA_RETENTION_MS);
    vi.setSystemTime(done + TASK_METADATA_RETENTION_MS);
    await runDurableObjectAlarm(s);
    expect(await s.get(T)).toBeNull();
    await deliverAlarm(s); // re-delivered after the purge
    expect(await s.get(T)).toBeNull();
  });

  it("an alarm for a missing task does nothing", async () => {
    const s = stub();
    await deliverAlarm(s);
    expect(await s.get(T)).toBeNull();
    expect(await stored(s)).toEqual({});
  });

  it("the state, the deadline and the alarm survive the object being evicted", async () => {
    const s = await fresh(1000);
    const exp = (await rec(s)).expires_at;
    await asTarget(s, "INPUT_REQUIRED", 1);
    await evictDurableObject(s);
    expect(await rec(s)).toMatchObject({ state: "INPUT_REQUIRED", target_seq: 1, expires_at: exp });
    expect(await asTarget(s, "WORKING", 1)).toBe("bad_seq"); // the sequence survived too
    await evictDurableObject(s);
    vi.setSystemTime(exp + 1);
    expect(await runDurableObjectAlarm(s)).toBe(true);
    await evictDurableObject(s);
    expect(await s.get(T)).toMatchObject({ state: "FAILED", reason: "expired" });
    expect(await asCaller(s, "REPLY", 1)).toBe("terminal");
  });

  it("a clock that steps back never moves `updated` back, and a long-ago task still expires", async () => {
    const s = await fresh(10_000);
    const t0 = (await rec(s)).created;
    vi.setSystemTime(t0 + 5000);
    await asTarget(s, "WORKING", 1);
    const u = (await rec(s)).updated;
    expect(u).toBe(t0 + 5000);
    vi.setSystemTime(t0 + 100); // skewed behind
    expect(await asTarget(s, "INPUT_REQUIRED", 2)).toMatchObject({ updated: u });
    expect(await state(s)).toBe("INPUT_REQUIRED"); // not yet expired on the skewed clock
    expect(await asCaller(s, "CANCEL", 1)).toMatchObject({ state: "CANCELED", updated: u });
  });

  it("a clock that jumps far ahead expires the task and anchors retention at the deadline", async () => {
    const s = await fresh(1000);
    const exp = (await rec(s)).expires_at;
    vi.setSystemTime(exp + 400 * 24 * 3600_000);
    expect(await runDurableObjectAlarm(s)).toBe(true);
    // The deadline was a year ago, so retention is also over: purged on the same delivery.
    expect(await s.get(T)).toBeNull();
  });

  it("a live task with a long deadline is not expired by an alarm delivered late but still before it", async () => {
    const s = await fresh(TASK_TTL_MAX_MS);
    vi.setSystemTime(Date.now() + 1000);
    await deliverAlarm(s);
    expect(await state(s)).toBe("SUBMITTED");
  });
});


// Retention modes: Queued holds sealed events for an offline caller until the
// caller acknowledges them or the TTL passes; Strict holds nothing.
describe("retention", () => {
  const HOUR = QUEUE_TTL_DEFAULT_MS;
  const queued = async () => {
    const s = stub();
    expect(typeof (await s.create({ tenant: T, id: "abc", caller: "alice", target: "bob", retention: "queued" }))).toBe("object");
    return s;
  };
  const hold = (s: Stub, body = "sealed", ttl = HOUR) => s.enqueue(T, "bob", body, ttl);
  const heldKeys = async (s: Stub) => Object.keys(await stored(s)).filter((k) => k.startsWith("q:"));
  beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));

  it("the queue TTL is 1 hour by default, from 15 minutes to 24 hours", () => {
    expect([QUEUE_TTL_DEFAULT_MS, QUEUE_TTL_MIN_MS, QUEUE_TTL_MAX_MS]).toEqual([3600_000, 900_000, 86_400_000]);
  });

  it("a task is Strict by default, and a Strict task holds nothing", async () => {
    const s = await fresh();
    expect((await rec(s)).retention).toBe("strict");
    expect(await hold(s)).toBe("not_queued");
    expect(Object.keys(await stored(s))).toEqual(["task"]);
  });

  it("holds an event for the caller with its own deadline, and the alarm is the earliest deadline", async () => {
    const s = await queued();
    const r = await rec(s);
    const t0 = Date.now();
    expect(await hold(s, "one", HOUR)).toEqual({ id: 1, expires_at: t0 + HOUR });
    expect(await alarmOf(s)).toBe(r.expires_at); // the task expires (15 min) before the event does
    expect(await hold(s, "two", QUEUE_TTL_MIN_MS)).toEqual({ id: 2, expires_at: t0 + QUEUE_TTL_MIN_MS });
    expect((await rec(s)).queue_until).toBe(t0 + QUEUE_TTL_MIN_MS);
    expect(await heldKeys(s)).toEqual(["q:000000000001", "q:000000000002"]);
    expect(await s.drain(T, "alice")).toEqual([
      { id: 1, body: "one", exp: t0 + HOUR },
      { id: 2, body: "two", exp: t0 + QUEUE_TTL_MIN_MS },
    ]);
  });

  it("a long task TTL keeps the event deadline as the alarm", async () => {
    const s = stub();
    await s.create({ tenant: T, id: "abc", caller: "alice", target: "bob", retention: "queued", ttl_ms: TASK_TTL_MAX_MS });
    const r = await hold(s, "x", QUEUE_TTL_MIN_MS);
    expect(await alarmOf(s)).toBe((r as { expires_at: number }).expires_at);
  });

  it("refuses bad input, the wrong sender, another tenant, and a full queue, and stores nothing for them", async () => {
    const s = await queued();
    for (const body of ["", 5 as unknown as string, "x".repeat(MAX_QUEUED_BYTES)]) expect(await hold(s, body)).toBe("bad_request");
    for (const ttl of [QUEUE_TTL_MIN_MS - 1, QUEUE_TTL_MAX_MS + 1, 1.5, NaN]) expect(await hold(s, "x", ttl)).toBe("bad_request");
    expect(await s.enqueue(T, "alice", "x", HOUR)).toBe("forbidden"); // the caller's own messages are never held
    expect(await s.enqueue(T, "mallory", "x", HOUR)).toBe("forbidden");
    expect(await s.enqueue("t2", "bob", "x", HOUR)).toBe("not_found");
    expect(await stub().enqueue(T, "bob", "x", HOUR)).toBe("not_found");
    expect(await heldKeys(s)).toEqual([]);
    expect((await rec(s)).qseq).toBe(0);
    for (let i = 0; i < MAX_QUEUED; i++) expect(typeof (await hold(s))).toBe("object");
    expect(await hold(s)).toBe("full");
    expect(await heldKeys(s)).toHaveLength(MAX_QUEUED);
  });

  it("refuses an event that would take the task past its byte limit", async () => {
    const s = await queued();
    const big = "x".repeat(1 << 20);
    for (let i = 0; i < 4; i++) expect(typeof (await hold(s, big))).toBe("object");
    expect(await hold(s, "x")).toBe("full");
  });

  it("only the caller can drain and acknowledge", async () => {
    const s = await queued();
    await hold(s);
    for (const who of ["bob", "mallory"]) {
      expect(await s.drain(T, who)).toBe("forbidden");
      expect(await s.ack(T, who, 1)).toBe("forbidden");
    }
    expect(await s.drain("t2", "alice")).toBe("not_found");
    expect(await s.ack("t2", "alice", 1)).toBe("not_found");
    expect(await heldKeys(s)).toHaveLength(1);
  });

  it("an acknowledged event is deleted at once, and the record says when", async () => {
    const s = await queued();
    await hold(s, "one");
    await hold(s, "two");
    expect(await s.ack(T, "alice", 1)).toBe(1);
    expect(await heldKeys(s)).toEqual(["q:000000000002"]);
    expect((await rec(s)).ciphertext_deleted_at).toBeUndefined(); // one is still held
    vi.setSystemTime(Date.now() + 1000);
    const t = Date.now();
    expect(await s.ack(T, "alice", 1)).toBe(1); // a repeat changes nothing
    expect(await s.ack(T, "alice", 2)).toBe(0);
    expect(await heldKeys(s)).toEqual([]);
    const r = await rec(s);
    expect(r.ciphertext_deleted_at).toBe(t);
    expect(r.queue_until).toBeUndefined();
    expect(await s.drain(T, "alice")).toEqual([]);
    // Holding another clears the "deleted" record, and the ids keep counting.
    expect(await hold(s, "three")).toMatchObject({ id: 3 });
    expect((await rec(s)).ciphertext_deleted_at).toBeUndefined();
  });

  it("deletes a held event at its TTL, from the alarm, and keeps the task's other deadline", async () => {
    const s = stub();
    await s.create({ tenant: T, id: "abc", caller: "alice", target: "bob", retention: "queued", ttl_ms: TASK_TTL_MAX_MS });
    const t0 = Date.now();
    await hold(s, "short", QUEUE_TTL_MIN_MS);
    await hold(s, "long", HOUR);
    vi.setSystemTime(t0 + QUEUE_TTL_MIN_MS - 1);
    await deliverAlarm(s); // early: nothing is deleted
    expect(await heldKeys(s)).toHaveLength(2);
    vi.setSystemTime(t0 + QUEUE_TTL_MIN_MS);
    await deliverAlarm(s);
    expect(await heldKeys(s)).toEqual(["q:000000000002"]);
    const r = await rec(s);
    expect(r.state).toBe("SUBMITTED"); // the task itself is still alive
    expect(r.queue_until).toBe(t0 + HOUR);
    expect(r.ciphertext_deleted_at).toBeUndefined();
    expect(await alarmOf(s)).toBe(t0 + HOUR); // the next held event, ahead of the 90-day purge
    vi.setSystemTime(t0 + HOUR);
    await deliverAlarm(s);
    expect(await heldKeys(s)).toEqual([]);
    expect((await rec(s)).ciphertext_deleted_at).toBe(t0 + HOUR);
    expect(await alarmOf(s)).toBe(r.expires_at);
    expect(await s.drain(T, "alice")).toEqual([]);
  });

  it("canceling the task deletes every held event at once", async () => {
    const s = await queued();
    await hold(s, "one");
    await hold(s, "two");
    await s.apply(T, "alice", "CANCEL", 1);
    expect(await heldKeys(s)).toEqual([]);
    const r = await rec(s);
    expect(r.ciphertext_deleted_at).toBe(Date.now());
    expect(r.queue_until).toBeUndefined();
    expect(await hold(s, "late")).toBe("not_queued"); // a message racing the cancel is not kept
    expect(await heldKeys(s)).toEqual([]);
  });

  it("expiry deletes every held event, at the alarm and on a read, long before its TTL", async () => {
    for (const via of ["alarm", "read"] as const) {
      const s = stub();
      await s.create({ tenant: T, id: `e${via}`, caller: "alice", target: "bob", retention: "queued", ttl_ms: QUEUE_TTL_MIN_MS });
      await hold(s, "x", QUEUE_TTL_MAX_MS);
      vi.setSystemTime(Date.now() + QUEUE_TTL_MIN_MS);
      if (via === "alarm") await deliverAlarm(s);
      else expect(await s.drain(T, "alice")).toEqual([]);
      expect(await heldKeys(s)).toEqual([]);
      expect(await hold(s, "late")).toBe("not_queued");
      expect((await rec(s)).ciphertext_deleted_at).toBeGreaterThan(0);
    }
  });

  it("a dropped caller socket deletes held events", async () => {
    const s = await queued();
    await hold(s, "x");
    await s.callerDisconnected(T, "alice");
    expect(await heldKeys(s)).toEqual([]);
  });

  it("never returns an event past its TTL, even before the alarm has run", async () => {
    const s = await queued();
    await hold(s, "x", QUEUE_TTL_MIN_MS);
    vi.setSystemTime(Date.now() + QUEUE_TTL_MIN_MS);
    expect(await s.drain(T, "alice")).toEqual([]);
    expect(await heldKeys(s)).toEqual([]);
  });

  it("a state change does not push the event deadline back", async () => {
    const s = await queued();
    const t0 = Date.now();
    await hold(s, "x", QUEUE_TTL_MIN_MS);
    await asTarget(s, "COMPLETED", 1); // terminal: the next base deadline is 90 days out
    expect(await alarmOf(s)).toBe(t0 + QUEUE_TTL_MIN_MS);
    vi.setSystemTime(t0 + QUEUE_TTL_MIN_MS);
    await deliverAlarm(s);
    expect(await heldKeys(s)).toEqual([]);
    expect(await alarmOf(s)).toBe(t0 + TASK_METADATA_RETENTION_MS);
  });

  it("purging the task's metadata deletes anything still held", async () => {
    const s = await queued();
    await hold(s, "x", QUEUE_TTL_MAX_MS);
    await asTarget(s, "COMPLETED", 1);
    vi.setSystemTime(Date.now() + TASK_METADATA_RETENTION_MS);
    await deliverAlarm(s);
    expect(await stored(s)).toEqual({});
  });

  it("holds only sealed bodies and ids, never a key that could carry readable content", async () => {
    const s = await queued();
    await hold(s, "sealed-body");
    const all = await stored(s);
    expect(Object.keys(all).sort()).toEqual(["q:000000000001", "task"]);
    expect(all["q:000000000001"]).toEqual({ body: "sealed-body", exp: Date.now() + HOUR });
  });

  it("survives eviction", async () => {
    const s = await queued();
    await hold(s, "x");
    await evictDurableObject(s);
    expect(await s.drain(T, "alice")).toHaveLength(1);
  });
});

// Parts of the retention acceptance that need the whole system (daemon, R2 file store) come with T307.
describe("T307 retention deletion acceptance", () => {
  it.todo("T307: a daemon-acknowledged result is gone from Task DO storage and the encrypted-file R2 objects are deleted and verified absent");
  it.todo("T307: Queued TTL deletion with a real daemon reconnect after the TTL receives nothing");
});
