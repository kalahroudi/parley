// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TASK_METADATA_RETENTION_MS, TASK_TTL_DEFAULT_MS, TASK_TTL_MAX_MS, TERMINAL, type Task, type TaskEvent, type TaskRecord, type TaskState } from "../src/task";

let n = 0;
const stub = () => env.TASK.get(env.TASK.idFromName(`t1:task${++n}`)) as DurableObjectStub<Task>;
const fresh = async (ttl_ms?: number) => {
  const s = stub();
  const r = await s.create({ id: "abc", caller: "alice", target: "bob", ttl_ms });
  expect(typeof r).toBe("object");
  return s;
};
const asTarget = (s: DurableObjectStub<Task>, e: TaskEvent, seq: number) => s.apply("target", "bob", e, seq);
const asCaller = (s: DurableObjectStub<Task>, e: TaskEvent, seq: number) => s.apply("caller", "alice", e, seq);
const state = async (s: DurableObjectStub<Task>) => (await s.get())!.state;

afterEach(() => vi.useRealTimers());

describe("create", () => {
  it("starts SUBMITTED with the default expiry and metadata only", async () => {
    const t0 = Date.now();
    const r = (await stub().create({ id: "abc", caller: "alice", target: "bob" })) as TaskRecord;
    expect(r).toMatchObject({ state: "SUBMITTED", seq: 0, caller: "alice", target: "bob" });
    expect(r.expires_at - t0).toBeGreaterThanOrEqual(TASK_TTL_DEFAULT_MS);
    expect(Object.keys(r).sort()).toEqual(["caller", "created", "expires_at", "id", "seq", "state", "target", "updated"]);
  });

  it("rejects bad input and a second create", async () => {
    const s = stub();
    for (const bad of [{ id: "a/b" }, { caller: "" }, { target: "x".repeat(65) }, { ttl_ms: 0 }, { ttl_ms: -1 }, { ttl_ms: NaN }, { ttl_ms: TASK_TTL_MAX_MS + 1 }]) {
      expect(await s.create({ id: "abc", caller: "alice", target: "bob", ...bad })).toBe("bad_request");
    }
    expect(await s.get()).toBeNull();
    expect(typeof (await s.create({ id: "abc", caller: "alice", target: "bob", ttl_ms: TASK_TTL_MAX_MS }))).toBe("object");
    expect(await s.create({ id: "abc", caller: "alice", target: "bob" })).toBe("exists");
  });
});

describe("state machine", () => {
  const allStates: TaskState[] = ["SUBMITTED", "WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "CANCELED", "REJECTED"];
  // Path from SUBMITTED to each state.
  const reach: Record<TaskState, (s: DurableObjectStub<Task>) => Promise<number>> = {
    SUBMITTED: async () => 0,
    WORKING: async (s) => (await asTarget(s, "WORKING", 1), 1),
    INPUT_REQUIRED: async (s) => (await asTarget(s, "INPUT_REQUIRED", 1), 1),
    COMPLETED: async (s) => (await asTarget(s, "COMPLETED", 1), 1),
    FAILED: async (s) => (await asTarget(s, "FAILED", 1), 1),
    CANCELED: async (s) => (await asCaller(s, "CANCEL", 1), 1),
    REJECTED: async (s) => (await asTarget(s, "REJECTED", 1), 1),
  };
  const targetEvents: TaskEvent[] = ["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "REJECTED"];
  const allowed: Record<TaskState, string[]> = {
    SUBMITTED: ["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "REJECTED", "CANCEL"],
    WORKING: ["INPUT_REQUIRED", "COMPLETED", "FAILED", "CANCEL"],
    INPUT_REQUIRED: ["WORKING", "COMPLETED", "FAILED", "CANCEL", "REPLY"],
    COMPLETED: [],
    FAILED: [],
    CANCELED: [],
    REJECTED: [],
  };

  for (const from of allStates) {
    for (const ev of [...targetEvents, "CANCEL", "REPLY"] as TaskEvent[]) {
      const ok = allowed[from].includes(ev);
      it(`${from} + ${ev} is ${ok ? "accepted" : "refused"}`, async () => {
        const s = await fresh();
        const seq = await reach[from](s);
        expect(await state(s)).toBe(from);
        const r = ev === "CANCEL" || ev === "REPLY" ? await asCaller(s, ev, seq + 1) : await asTarget(s, ev, seq + 1);
        if (ok) {
          const to = ev === "CANCEL" ? "CANCELED" : ev === "REPLY" ? "WORKING" : ev;
          expect(r).toMatchObject({ state: to, seq: seq + 1 });
        } else {
          expect(r).toBe(TERMINAL.has(from) ? "terminal" : "bad_transition");
          expect(await state(s)).toBe(from);
          expect((await s.get())!.seq).toBe(seq);
        }
      });
    }
  }

  it("runs the full question and answer lifecycle", async () => {
    const s = await fresh();
    await asTarget(s, "WORKING", 1);
    await asTarget(s, "INPUT_REQUIRED", 2);
    await asCaller(s, "REPLY", 3);
    await asTarget(s, "INPUT_REQUIRED", 4);
    await asCaller(s, "REPLY", 5);
    expect(await asTarget(s, "COMPLETED", 6)).toMatchObject({ state: "COMPLETED", reason: "target" });
  });

  it("refuses the wrong actor, the wrong device and events outside the actor's role", async () => {
    const s = await fresh();
    expect(await s.apply("caller", "bob", "CANCEL", 1)).toBe("forbidden");
    expect(await s.apply("target", "alice", "WORKING", 1)).toBe("forbidden");
    expect(await s.apply("target", "mallory", "WORKING", 1)).toBe("forbidden");
    expect(await s.apply("caller", "alice", "COMPLETED", 1)).toBe("forbidden"); // the caller cannot complete its own task
    expect(await s.apply("target", "bob", "CANCEL", 1)).toBe("forbidden");
    expect(await s.apply("target", "bob", "REPLY", 1)).toBe("forbidden");
    expect(await state(s)).toBe("SUBMITTED");
  });

  it("requires strictly increasing sequence numbers", async () => {
    const s = await fresh();
    await asTarget(s, "WORKING", 5);
    for (const seq of [5, 4, 0, -1, 1.5, NaN]) expect(await asTarget(s, "INPUT_REQUIRED", seq)).toBe("bad_seq");
    expect(await asTarget(s, "INPUT_REQUIRED", 7)).toMatchObject({ seq: 7 });
  });

  it("reports an unknown task", async () => {
    const s = stub();
    expect(await asCaller(s, "CANCEL", 1)).toBe("not_found");
    expect(await s.callerDisconnected()).toBe("not_found");
    expect(await s.get()).toBeNull();
  });

  it("makes a late reply after CANCEL impossible", async () => {
    const s = await fresh();
    await asTarget(s, "WORKING", 1);
    expect(await asCaller(s, "CANCEL", 2)).toMatchObject({ state: "CANCELED", reason: "canceled" });
    for (const e of ["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "REJECTED"] as const) expect(await asTarget(s, e, 3)).toBe("terminal");
    expect(await asCaller(s, "CANCEL", 3)).toBe("terminal");
    expect(await state(s)).toBe("CANCELED");
  });

  it("serializes racing cancel and complete: exactly one wins", async () => {
    const s = await fresh();
    await asTarget(s, "WORKING", 1);
    const [a, b] = await Promise.all([asCaller(s, "CANCEL", 2), asTarget(s, "COMPLETED", 2)]);
    expect([typeof a, typeof b].sort()).toEqual(["object", "string"]);
    expect(TERMINAL.has(await state(s))).toBe(true);
  });
});

describe("deadlines and expiry", () => {
  beforeEach(() => vi.useFakeTimers({ toFake: ["Date"] }));

  it("fails a live task at its deadline, on read, without the alarm", async () => {
    const s = await fresh(1000);
    await asTarget(s, "WORKING", 1);
    vi.setSystemTime(Date.now() + 999);
    expect(await state(s)).toBe("WORKING");
    vi.setSystemTime(Date.now() + 2);
    expect(await s.get()).toMatchObject({ state: "FAILED", reason: "expired" });
  });

  it("refuses updates after the deadline", async () => {
    const s = await fresh(1000);
    vi.setSystemTime(Date.now() + 1000);
    expect(await asTarget(s, "COMPLETED", 1)).toBe("terminal");
    expect(await asCaller(s, "CANCEL", 2)).toBe("terminal");
    expect((await s.get())!.reason).toBe("expired");
  });

  it("the alarm expires the task and arms the metadata purge", async () => {
    const s = await fresh(1000);
    await runInDurableObject(s, async (_, ctx) => expect(await ctx.storage.getAlarm()).not.toBeNull());
    vi.setSystemTime(Date.now() + 1001);
    expect(await runDurableObjectAlarm(s)).toBe(true);
    expect(await s.get()).toMatchObject({ state: "FAILED", reason: "expired" });
    await runInDurableObject(s, async (_, ctx) => expect(await ctx.storage.getAlarm()).toBeGreaterThan(Date.now()));
  });

  it("the alarm after retention deletes the record", async () => {
    const s = await fresh(1000);
    await asTarget(s, "REJECTED", 1);
    vi.setSystemTime(Date.now() + TASK_METADATA_RETENTION_MS - 1);
    expect(await runDurableObjectAlarm(s)).toBe(true); // not yet due: re-armed
    expect(await s.get()).not.toBeNull();
    vi.setSystemTime(Date.now() + 2);
    await runDurableObjectAlarm(s);
    expect(await s.get()).toBeNull();
  });

  it("an alarm for a missing task does nothing", async () => {
    const s = stub();
    await runInDurableObject(s, (o) => o.alarm());
    expect(await s.get()).toBeNull();
  });

  it("a caller that disconnects fails a live task once and leaves a finished one alone", async () => {
    const s = await fresh();
    expect(await s.callerDisconnected()).toMatchObject({ state: "FAILED", reason: "disconnected" });
    expect(await asTarget(s, "COMPLETED", 1)).toBe("terminal");
    const done = await fresh();
    await asTarget(done, "COMPLETED", 1);
    expect(await done.callerDisconnected()).toMatchObject({ state: "COMPLETED" });
  });
});
