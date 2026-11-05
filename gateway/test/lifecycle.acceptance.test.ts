// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T306 acceptance. Two things the unit suites (task.test.ts, a2a.test.ts) do not
// prove on their own:
//  1. The task state machine, exhaustively over event SEQUENCES (every path of up
//     to three events from SUBMITTED), checked against a reference model written
//     here independently of the table in src/task.ts, plus expiry from every state.
//  2. The official A2A SDK (@a2a-js/sdk) client, as both the caller and the target,
//     completes whole lifecycles against the gateway with opaque sealed parts:
//     SUBMITTED, WORKING, INPUT_REQUIRED, a reply on the same task, COMPLETED, and
//     the FAILED, REJECTED and CANCELED endings, with A2A errors by code.

import { env, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentCard, Role, Task, TaskState } from "@a2a-js/sdk";
import { ClientFactory, ClientFactoryOptions, JsonRpcTransportFactory } from "@a2a-js/sdk/client";
import { TaskNotFoundError } from "@a2a-js/sdk/errors";
import { SEALED_MEDIA_TYPE } from "../src/a2a";
import type { SignedKind } from "../src/parts";
import { NEXT } from "../src/task";
import type { Task as TaskDO, TaskEvent, TaskRecord, TaskState as State } from "../src/task";
import { b64, encodeWire, gw, header, taskBytes, taskHex } from "./wire";

afterEach(() => vi.useRealTimers());

// ---------------------------------------------------------------- 1. the machine

// The whole machine, restated by hand: (state, event) -> next state. An absent
// entry is a refusal. Not derived from NEXT, so a wrong edge in either place fails.
const MODEL: Record<string, Record<string, State>> = {
  SUBMITTED: { WORKING: "WORKING", INPUT_REQUIRED: "INPUT_REQUIRED", COMPLETED: "COMPLETED", FAILED: "FAILED", REJECTED: "REJECTED", CANCEL: "CANCELED" },
  WORKING: { WORKING: "WORKING", INPUT_REQUIRED: "INPUT_REQUIRED", COMPLETED: "COMPLETED", FAILED: "FAILED", CANCEL: "CANCELED" },
  INPUT_REQUIRED: { WORKING: "WORKING", COMPLETED: "COMPLETED", FAILED: "FAILED", CANCEL: "CANCELED", REPLY: "WORKING" },
  COMPLETED: {},
  FAILED: {},
  CANCELED: {},
  REJECTED: {},
};
const PATHS = 49;
const EVENTS: TaskEvent[] = ["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "REJECTED", "CANCEL", "REPLY"];
const FROM_CALLER = new Set<TaskEvent>(["CANCEL", "REPLY"]);
const terminal = (s: string) => Object.keys(MODEL[s]!).length === 0;

// Every path of at most `depth` events. Two is the whole table: the machine's next state
// depends on the current state and the event alone, so every (state, event) pair is the
// second step of some path (each of the seven states is one event from SUBMITTED, or SUBMITTED
// itself). Deeper paths repeat pairs already covered and only cost durable storage writes,
// which are ~25 ms each on Windows runners and starve the other test files there. A path that reaches a terminal state gets
// one more step (every event, all refused) and stops there: nothing after it can differ.
function paths(depth: number, from = "SUBMITTED", prefix: TaskEvent[] = []): TaskEvent[][] {
  if (prefix.length === depth) return [prefix];
  if (terminal(from)) return EVENTS.map((e) => [...prefix, e]);
  return EVENTS.flatMap((e) => paths(depth, MODEL[from]![e] ?? from, [...prefix, e]));
}

let k = 0;
const taskStub = () => env.TASK.get(env.TASK.idFromName(`seq:t${++k}`)) as DurableObjectStub<TaskDO>;
const fresh = async () => {
  const s = taskStub();
  expect(typeof (await s.create({ tenant: "seq", id: "abc", caller: "alice", target: "bob" }))).toBe("object");
  return s;
};

describe("the task state machine, over every event sequence", () => {
  it("the model here and the table in src/task.ts allow exactly the same edges, so drift in either fails", () => {
    expect(Object.keys(MODEL).sort()).toEqual(Object.keys(NEXT).sort());
    for (const [from, edges] of Object.entries(MODEL)) expect([...new Set(Object.values(edges))].sort(), from).toEqual([...NEXT[from as State]].sort());
  });

  it("covers every path of up to two events (every state with every event), and each ends where the model says", async () => {
    const all = paths(2);
    expect(all.length).toBe(PATHS);
    // Every (state, event) pair of the model is the last step of some path.
    const pairs = new Set<string>();
    for (const p of all) {
      let st = "SUBMITTED";
      for (const ev of p) { pairs.add(`${st} ${ev}`); st = MODEL[st]![ev] ?? st; }
    }
    for (const st of Object.keys(MODEL)) for (const ev of EVENTS) expect(pairs.has(`${st} ${ev}`), `${st} ${ev} is exercised`).toBe(true);
    for (const path of all) {
      const s = await fresh();
      let st = "SUBMITTED";
      const seqs = { alice: 0, bob: 0 };
      const label = path.join(" > ");
      for (const [i, ev] of path.entries()) {
        const who = FROM_CALLER.has(ev) ? "alice" : "bob";
        const before = (await s.get("seq")) as TaskRecord;
        const to = MODEL[st]![ev];
        const r = await s.apply("seq", who, ev, seqs[who] + 1);
        const at = `${label} (step ${i + 1}: ${ev} in ${st})`;
        if (to) {
          expect(r, at).toMatchObject({ state: to, [`${who === "alice" ? "caller" : "target"}_seq`]: seqs[who] + 1 });
          seqs[who]++;
          st = to;
        } else {
          expect(r, at).toBe(terminal(st) ? "terminal" : "bad_transition");
          expect(await s.get("seq"), at).toEqual(before); // a refusal changes nothing
        }
      }
      expect(((await s.get("seq")) as TaskRecord).state, label).toBe(st);
    }
  }, 120_000);

  it("a terminal state is final: no sequence of any party's events moves it", async () => {
    for (const end of ["COMPLETED", "FAILED", "REJECTED", "CANCELED"] as const) {
      const s = await fresh();
      await s.apply("seq", end === "CANCELED" ? "alice" : "bob", end === "CANCELED" ? "CANCEL" : end, 1);
      const done = (await s.get("seq")) as TaskRecord;
      for (const who of ["alice", "bob", "mallory"]) for (const ev of EVENTS) for (const seq of [1, 2, 99]) expect(typeof (await s.apply("seq", who, ev, seq)), `${end} ${who} ${ev}`).toBe("string");
      expect(await s.get("seq")).toEqual(done);
    }
  });

  it("every non-terminal state expires into FAILED (expired), and a terminal state keeps its outcome", async () => {
    const reach: Record<string, (s: DurableObjectStub<TaskDO>) => Promise<unknown>> = {
      SUBMITTED: async () => undefined,
      WORKING: (s) => s.apply("seq", "bob", "WORKING", 1),
      INPUT_REQUIRED: (s) => s.apply("seq", "bob", "INPUT_REQUIRED", 1),
      COMPLETED: (s) => s.apply("seq", "bob", "COMPLETED", 1),
      FAILED: (s) => s.apply("seq", "bob", "FAILED", 1),
      REJECTED: (s) => s.apply("seq", "bob", "REJECTED", 1),
      CANCELED: (s) => s.apply("seq", "alice", "CANCEL", 1),
    };
    vi.useFakeTimers({ toFake: ["Date"] });
    for (const [from, go] of Object.entries(reach)) {
      for (const how of ["read", "alarm"] as const) {
        const s = await fresh();
        await go(s);
        const rec = (await s.get("seq")) as TaskRecord;
        expect(rec.state).toBe(from);
        vi.setSystemTime(rec.expires_at + 1);
        if (how === "alarm") await runInDurableObject<TaskDO, void>(s, (o) => o.alarm());
        const after = (await s.get("seq")) as TaskRecord;
        const at = `${from} after expiry (${how})`;
        if (terminal(from)) expect(after, at).toEqual(rec);
        else expect(after, at).toMatchObject({ state: "FAILED", reason: "expired" });
        // Nothing is accepted after the deadline, from either side.
        for (const ev of EVENTS) expect(typeof (await s.apply("seq", FROM_CALLER.has(ev) ? "alice" : "bob", ev, 9)), `${at}: ${ev}`).toBe("string");
        vi.useRealTimers();
        vi.useFakeTimers({ toFake: ["Date"] });
      }
    }
  }, 120_000);
});

// ---------------------------------------------------------------- 2. the official SDK

let n = 0;
const tenant = () => `sdk${++n}`;
const sealed = (T: string, kind: SignedKind, task: string, from: string, to: string, seq: number) => encodeWire({ header: header(kind, { tenant: T, sender: from, target: to, task: taskBytes(task), seq }) });

async function tunnel(T: string, device: string) {
  const ws = (await gw("https://gw/v1/connect", { headers: { Upgrade: "websocket", Authorization: `Bearer dev:${T}:${device}` } })).webSocket!;
  ws.accept();
  const inbox: any[] = [];
  const waiters: ((m: any) => void)[] = [];
  ws.addEventListener("message", (e) => {
    const m = JSON.parse(e.data as string);
    const w = waiters.shift();
    if (w) w(m);
    else inbox.push(m);
  });
  ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
  const next = () => (inbox.length ? Promise.resolve(inbox.shift()) : new Promise<any>((r) => waiters.push(r)));
  await next(); // welcome
  return { event: async () => JSON.parse((await next()).body) };
}

// A party that talks to the gateway only through the SDK's client.
async function party(T: string, device: string) {
  const fetchImpl = (async (url: any, init: any) => gw(url, { ...init, headers: { ...(init?.headers ?? {}), Authorization: `Bearer dev:${T}:${device}` } })) as typeof fetch;
  const factory = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, { transports: [new JsonRpcTransportFactory({ fetchImpl })] }));
  const card = AgentCard.fromJSON(await (await gw("https://gw/.well-known/agent-card.json")).json());
  const client = await factory.createFromAgentCard(card);
  const events = await tunnel(T, device);
  const message = (role: Role, raw: Uint8Array, metadata?: Record<string, unknown>) =>
    ({ messageId: `m${++n}`, role, parts: [{ content: { $case: "raw", value: raw }, mediaType: SEALED_MEDIA_TYPE, filename: "", metadata: undefined }], contextId: "", taskId: "", metadata, extensions: [], referenceTaskIds: [] }) as any;
  const send = async (role: Role, raw: Uint8Array, metadata?: Record<string, unknown>) =>
    (await client.sendMessage({ message: message(role, raw, metadata), configuration: undefined, metadata: undefined, tenant: "" } as any)) as any;
  const get = (name: string) => client.getTask({ id: taskHex(name), historyLength: undefined, tenant: "" } as any);
  const cancel = (name: string, raw: Uint8Array) => client.cancelTask({ id: taskHex(name), metadata: { parley: { messageId: `c${++n}`, parts: [{ raw: b64(raw), mediaType: SEALED_MEDIA_TYPE }] } }, tenant: "" } as any);
  return { ...events, send, get, cancel };
}

// What the SDK says the response is: a Task, or a message-and-task wrapper.
const taskOf = (r: any): Task => (r?.payload?.$case === "task" ? r.payload.value : (r?.task ?? r?.payload?.value ?? r));
const stateOf = (t: any) => t.status?.state;

describe("the official A2A SDK completes a lifecycle", () => {
  it("SUBMITTED, WORKING, INPUT_REQUIRED, a reply on the same task, COMPLETED, each seen by the other side", async () => {
    const T = tenant();
    const alice = await party(T, "alice");
    const bob = await party(T, "bob");
    const id = taskHex("life");

    const made = taskOf(await alice.send(Role.ROLE_USER, sealed(T, "TASK", "life", "alice", "bob", 0)));
    expect(made.id).toBe(id);
    expect(stateOf(made)).toBe(TaskState.TASK_STATE_SUBMITTED);
    const arrived = await bob.event();
    expect(arrived.task.id).toBe(id);
    expect(arrived.task.status.message.parts).toEqual([{ raw: expect.any(String), mediaType: SEALED_MEDIA_TYPE }]);

    // The target answers with the SDK too: a sealed STATUS, then the question.
    expect(stateOf(taskOf(await bob.send(Role.ROLE_AGENT, sealed(T, "STATUS", "life", "bob", "alice", 1))))).toBe(TaskState.TASK_STATE_WORKING);
    expect((await alice.event()).task.status.state).toBe("TASK_STATE_WORKING");
    expect(stateOf(await alice.get("life"))).toBe(TaskState.TASK_STATE_WORKING);

    expect(stateOf(taskOf(await bob.send(Role.ROLE_AGENT, sealed(T, "INPUT_REQUIRED", "life", "bob", "alice", 2))))).toBe(TaskState.TASK_STATE_INPUT_REQUIRED);
    expect((await alice.event()).task.status.state).toBe("TASK_STATE_INPUT_REQUIRED");
    expect(stateOf(await bob.get("life"))).toBe(TaskState.TASK_STATE_INPUT_REQUIRED);

    // The reply goes on the same task, not a new one.
    const reply = taskOf(await alice.send(Role.ROLE_USER, sealed(T, "REPLY", "life", "alice", "bob", 1)));
    expect(reply.id).toBe(id);
    expect(stateOf(reply)).toBe(TaskState.TASK_STATE_WORKING);
    expect((await bob.event()).task.status.message.metadata.parley).toMatchObject({ kind: "REPLY", seq: 1 });

    const done = taskOf(await bob.send(Role.ROLE_AGENT, sealed(T, "RESULT", "life", "bob", "alice", 3)));
    expect(stateOf(done)).toBe(TaskState.TASK_STATE_COMPLETED);
    expect((await alice.event()).task.status.state).toBe("TASK_STATE_COMPLETED");
    for (const p of [alice, bob]) expect(stateOf(await p.get("life"))).toBe(TaskState.TASK_STATE_COMPLETED);

    // Done is done: a late message from either side is an A2A error, and the task is unchanged.
    await expect(bob.send(Role.ROLE_AGENT, sealed(T, "STATUS", "life", "bob", "alice", 4))).rejects.toThrow();
    await expect(alice.send(Role.ROLE_USER, sealed(T, "REPLY", "life", "alice", "bob", 2))).rejects.toThrow();
    expect(stateOf(await alice.get("life"))).toBe(TaskState.TASK_STATE_COMPLETED);
  });

  it("the target ends a task as FAILED or REJECTED, and the caller sees which", async () => {
    const T = tenant();
    const alice = await party(T, "alice");
    const bob = await party(T, "bob");
    for (const [name, hint, want] of [["failed", undefined, TaskState.TASK_STATE_FAILED], ["rejected", { parley: { kind: "REJECTED" } }, TaskState.TASK_STATE_REJECTED]] as const) {
      await alice.send(Role.ROLE_USER, sealed(T, "TASK", name, "alice", "bob", 0));
      await bob.event();
      const r = taskOf(await bob.send(Role.ROLE_AGENT, sealed(T, "ERROR", name, "bob", "alice", 1), hint));
      expect(stateOf(r), name).toBe(want);
      expect((await alice.event()).task.status.state, name).toBe(want === TaskState.TASK_STATE_FAILED ? "TASK_STATE_FAILED" : "TASK_STATE_REJECTED");
      expect(stateOf(await alice.get(name)), name).toBe(want);
    }
  });

  it("the caller cancels with the SDK's cancelTask, the target is told, and nothing is accepted after", async () => {
    const T = tenant();
    const alice = await party(T, "alice");
    const bob = await party(T, "bob");
    await alice.send(Role.ROLE_USER, sealed(T, "TASK", "cx", "alice", "bob", 0));
    await bob.event();
    await bob.send(Role.ROLE_AGENT, sealed(T, "STATUS", "cx", "bob", "alice", 1));
    await alice.event();

    const c = await alice.cancel("cx", sealed(T, "CANCEL", "cx", "alice", "bob", 1));
    expect(stateOf(c)).toBe(TaskState.TASK_STATE_CANCELED);
    expect((await bob.event()).task.status.state).toBe("TASK_STATE_CANCELED");
    expect(stateOf(await bob.get("cx"))).toBe(TaskState.TASK_STATE_CANCELED);

    // A late reply from the target and a second cancel are both refused.
    await expect(bob.send(Role.ROLE_AGENT, sealed(T, "RESULT", "cx", "bob", "alice", 2))).rejects.toThrow();
    await expect(alice.cancel("cx", sealed(T, "CANCEL", "cx", "alice", "bob", 2))).rejects.toThrow();
    expect(stateOf(await alice.get("cx"))).toBe(TaskState.TASK_STATE_CANCELED);
  });

  it("a stranger and a missing task look like no task, by the A2A error code", async () => {
    const T = tenant();
    const alice = await party(T, "alice");
    await party(T, "bob");
    const carol = await party(T, "carol");
    await alice.send(Role.ROLE_USER, sealed(T, "TASK", "priv", "alice", "bob", 0));
    await expect(carol.get("priv")).rejects.toBeInstanceOf(TaskNotFoundError);
    await expect(carol.get("nothing")).rejects.toBeInstanceOf(TaskNotFoundError);
    await expect(carol.cancel("priv", sealed(T, "CANCEL", "priv", "carol", "bob", 1))).rejects.toBeInstanceOf(TaskNotFoundError);
    expect(stateOf(await alice.get("priv"))).toBe(TaskState.TASK_STATE_SUBMITTED);
  });

  it("every task the SDK receives is a valid SDK Task, from the first message to the last", async () => {
    const T = tenant();
    const alice = await party(T, "alice");
    const bob = await party(T, "bob");
    const seen = [taskOf(await alice.send(Role.ROLE_USER, sealed(T, "TASK", "shape", "alice", "bob", 0)))];
    await bob.event();
    seen.push(taskOf(await bob.send(Role.ROLE_AGENT, sealed(T, "RESULT", "shape", "bob", "alice", 1))));
    seen.push(await alice.get("shape"));
    for (const t of seen) {
      expect(Task.toJSON(Task.fromJSON(Task.toJSON(t as any)))).toEqual(Task.toJSON(t as any));
      expect(t.id).toBe(taskHex("shape"));
      expect(t.contextId).toBeTruthy();
    }
  });
});
