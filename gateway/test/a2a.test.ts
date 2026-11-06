// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MAX_REQUEST_BYTES, SEALED_MEDIA_TYPE, STATE_NAME } from "../src/a2a";
import { MAX_BUCKET, SIGNED_TYPE, type SignedKind } from "../src/parts";
import { MAX_HELD } from "../src/device";
import { MAX_QUEUED, NEXT, QUEUE_TTL_MIN_MS, type TaskState } from "../src/task";
import { gw, b64, encodeWire, header, taskBytes, taskHex, type Header } from "./wire";

// Each test gets its own tenant, so devices and tasks never collide.
let n = 0;
const fresh = () => {
  const T = `a2a${++n}`;
  return { T, bearer: (d: string) => ({ Authorization: `Bearer dev:${T}:${d}` }) };
};

async function connect(T: string, device: string) {
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
  ws.send(JSON.stringify({ t: "hello", v: 1, last_rx: 0 }));
  const next = () => (inbox.length ? Promise.resolve(inbox.shift()) : new Promise<any>((r) => waiters.push(r)));
  expect((await next()).t).toBe("welcome");
  // Next delivered event, decoded.
  return { ws, event: async () => JSON.parse((await next()).body), pending: () => inbox.length };
}

const errCode = (r: any) => r.error?.code;
// The long state walks go through a Worker and several Durable Objects per step; Windows CI storage writes are ~24 ms each and the
// walk shares the machine with the other suites (it took over 60 s once), so Windows gets the global Windows allowance.
const LONG_WALK_MS = process.platform === "win32" ? 180_000 : 60_000;
const ROLE: Record<string, string> = { TASK: "ROLE_USER", REPLY: "ROLE_USER", CANCEL: "ROLE_USER" };

function world() {
  const { T, bearer } = fresh();
  const rpc = async (device: string, method: string, params: unknown, id: unknown = 1) => {
    const r = await gw("https://gw/a2a", { method: "POST", headers: bearer(device), body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) });
    expect(r.status).toBe(200);
    return (await r.json()) as any;
  };
  // A sealed part for `task` (a name of at most 16 bytes), as the signed header would say it.
  const part = (kind: SignedKind, task: string, from: string, to: string, seq = kind === "TASK" ? 0 : 1, over: Header = {}, bucket = 4096, ct?: Uint8Array) => ({
    raw: b64(encodeWire({ header: header(kind, { tenant: T, sender: from, target: to, task: taskBytes(task), seq, ...over }), bucket, ct })),
    mediaType: SEALED_MEDIA_TYPE,
  });
  // A SendMessage request for it. `hint` is the optional metadata.parley.kind; `over` replaces message fields.
  const msg = (kind: SignedKind, task: string, from: string, to: string, seq?: number, o: { hint?: string; message?: Record<string, unknown>; header?: Header; bucket?: number } = {}) => ({
    message: { messageId: `m${++n}`, role: ROLE[kind] ?? "ROLE_AGENT", parts: [part(kind, task, from, to, seq, o.header, o.bucket)], ...o.message },
    ...(o.hint ? {} : {}),
  });
  const hinted = (p: any, parley: Record<string, unknown>) => ({ message: { ...p.message, metadata: { parley } } });
  const task = (id: string, from = "alice", to = "bob") => rpc(from, "SendMessage", msg("TASK", id, from, to));
  // The target's messages and the caller's, by kind and sequence number.
  const bob = (kind: SignedKind, id: string, seq: number, hint?: string) => {
    const p = msg(kind, id, "bob", "alice", seq);
    return rpc("bob", "SendMessage", hint ? hinted(p, { kind: hint }) : p);
  };
  const alice = (kind: SignedKind, id: string, seq: number) => rpc("alice", "SendMessage", msg(kind, id, "alice", "bob", seq));
  const cancel = (id: string, seq: number, from = "alice", to = "bob") => rpc(from, "CancelTask", cancelParams(id, seq, from, to));
  const cancelParams = (id: string, seq: number, from = "alice", to = "bob", extra: Record<string, unknown> = {}) => ({
    id: taskHex(id),
    metadata: { parley: { messageId: "c1", parts: [part("CANCEL", id, from, to, seq)], ...extra } },
  });
  const state = async (id: string, dev = "alice") => (await rpc(dev, "GetTask", { id: taskHex(id) })).result.status.state;
  return { T, bearer, rpc, part, msg, hinted, task, bob, alice, cancel, cancelParams, state };
}

describe("agent card and endpoint", () => {
  it("serves the card at the well-known path with the transport facts", async () => {
    const r = await gw("https://gw/.well-known/agent-card.json");
    expect(r.status).toBe(200);
    const c: any = await r.json();
    expect(c.supportedInterfaces).toEqual([{ url: "https://gw/a2a", protocolBinding: "JSONRPC", protocolVersion: "1.0" }]);
    expect(c.capabilities).toEqual({ streaming: false, pushNotifications: false });
    expect(c.defaultInputModes).toEqual([SEALED_MEDIA_TYPE]);
    expect((await gw("https://gw/.well-known/agent-card.json", { method: "POST" })).status).toBe(405);
  });

  it("needs a device identity and a POST, and bounds the body", async () => {
    const { bearer } = fresh();
    expect((await gw("https://gw/a2a", { method: "POST", body: "{}" })).status).toBe(401);
    expect((await gw("https://gw/a2a", { headers: bearer("a") })).status).toBe(405);
    const big = "x".repeat(MAX_REQUEST_BYTES + 1);
    expect((await gw("https://gw/a2a", { method: "POST", headers: bearer("a"), body: big })).status).toBe(413);
    const lie = await gw("https://gw/a2a", { method: "POST", headers: { ...bearer("a"), "content-length": String(MAX_REQUEST_BYTES + 1) }, body: "{}" });
    expect(lie.status).toBe(413);
    // Multi-byte text is measured in bytes, not characters.
    const wide = "é".repeat(MAX_REQUEST_BYTES / 2 + 1);
    expect(wide.length).toBeLessThanOrEqual(MAX_REQUEST_BYTES);
    expect((await gw("https://gw/a2a", { method: "POST", headers: bearer("a"), body: wide })).status).toBe(413);
  });

  it("cuts off a body with no declared length at the cap, and reads one that fits", async () => {
    const { bearer } = fresh();
    let pulled = 0;
    const chunk = new Uint8Array(64 * 1024).fill(0x78);
    // Well over the cap, with no length declared: the gateway must stop reading at the cap.
    const endless = new ReadableStream<Uint8Array>({
      pull(c) {
        pulled += chunk.length;
        c.enqueue(chunk);
        if (pulled >= 4 * MAX_REQUEST_BYTES) c.close();
      },
    });
    const r = await gw("https://gw/a2a", { method: "POST", headers: bearer("a"), body: endless, duplex: "half" } as RequestInit);
    expect(r.status).toBe(413);
    expect(pulled).toBeLessThan(4 * MAX_REQUEST_BYTES); // not read to the end
    // The same body split over several chunks is read whole.
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "GetTask", params: { id: taskHex("nope") } });
    const bytes = new TextEncoder().encode(body);
    const parts = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(bytes.subarray(0, 10));
        c.enqueue(bytes.subarray(10));
        c.close();
      },
    });
    const ok = await gw("https://gw/a2a", { method: "POST", headers: bearer("a"), body: parts, duplex: "half" } as RequestInit);
    expect(errCode(await ok.json())).toBe(-32001);
    // A body that is not UTF-8 is a parse error, and an empty one too.
    const bad = await gw("https://gw/a2a", { method: "POST", headers: bearer("a"), body: Uint8Array.of(0xff, 0xfe, 0x7b) });
    expect(errCode(await bad.json())).toBe(-32700);
    expect(errCode(await (await gw("https://gw/a2a", { method: "POST", headers: bearer("a") })).json())).toBe(-32700);
  });

  it("answers malformed JSON-RPC with the standard errors and never echoes input", async () => {
    const { bearer } = fresh();
    const post = async (body: string) => (await (await gw("https://gw/a2a", { method: "POST", headers: bearer("a"), body })).json()) as any;
    expect(errCode(await post("{nope"))).toBe(-32700);
    for (const b of ['[]', '"x"', '{"jsonrpc":"1.0","method":"GetTask"}', '{"jsonrpc":"2.0"}', '{"jsonrpc":"2.0","method":"GetTask","id":{}}', '{"jsonrpc":"2.0","method":"GetTask","id":true}', `{"jsonrpc":"2.0","method":"GetTask","id":"${"x".repeat(129)}"}`]) {
      expect(errCode(await post(b)), b).toBe(-32600);
    }
    expect(errCode(await post('{"jsonrpc":"2.0","method":"GetTask","id":1}'))).toBe(-32602);
    expect(errCode(await post('{"jsonrpc":"2.0","method":"GetTask","id":1,"params":[]}'))).toBe(-32602);
    const r = await post('{"jsonrpc":"2.0","method":"CANARY-METHOD","id":"CANARY-ID","params":{}}');
    expect(errCode(r)).toBe(-32601);
    expect(r.id).toBe("CANARY-ID");
    expect(JSON.stringify(r.error)).not.toContain("CANARY");
    expect(r.error.message).toBe("method not found");
    // The tenant field is the authenticated tenant or empty.
    expect(errCode(await post(`{"jsonrpc":"2.0","method":"GetTask","id":1,"params":{"id":"${taskHex("x")}","tenant":"other"}}`))).toBe(-32602);
    expect(errCode(await post(`{"jsonrpc":"2.0","method":"GetTask","id":1,"params":{"id":"${taskHex("x")}","tenant":""}}`))).toBe(-32001);
  });

  it("declines what the MVP does not offer", async () => {
    const { rpc } = world();
    for (const m of ["ListTasks", "SendStreamingMessage", "SubscribeToTask", "GetExtendedAgentCard"]) expect(errCode(await rpc("a", m, {})), m).toBe(-32004);
    for (const m of ["CreateTaskPushNotificationConfig", "GetTaskPushNotificationConfig", "ListTaskPushNotificationConfigs", "DeleteTaskPushNotificationConfig"]) {
      expect(errCode(await rpc("a", m, {})), m).toBe(-32003);
    }
  });
});

describe("what a standard A2A client sends", () => {
  it("accepts the standard configuration, tenant, and an omitted task id, and refuses the rest", async () => {
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    const base = w.msg("TASK", "tk", "alice", "bob");
    const send = (extra: Record<string, unknown>, id = "tk") => w.rpc("alice", "SendMessage", { ...w.msg("TASK", id, "alice", "bob"), ...extra });
    expect(errCode(await send({ configuration: { acceptedOutputModes: ["text/plain"] } }, "c1"))).toBe(-32005);
    expect(errCode(await send({ configuration: { taskPushNotificationConfig: { url: "https://x" } } }, "c2"))).toBe(-32003);
    for (const [i, bad] of [{ extra: 1 }, [], { historyLength: -1 }, { historyLength: 1.5 }, { returnImmediately: "yes" }, { acceptedOutputModes: "x" }, { acceptedOutputModes: [1] }, { acceptedOutputModes: Array(17).fill("a") }, { acceptedOutputModes: ["a".repeat(129)] }].entries()) {
      expect(errCode(await send({ configuration: bad }, `b${i}`)), JSON.stringify(bad)).toBe(-32602);
    }
    expect(errCode(await send({ metadata: { note: "x" } }, "m1"))).toBe(-32602);
    expect(errCode(await send({ tenant: "other" }, "m2"))).toBe(-32602);
    // None of those created a task.
    expect(errCode(await w.rpc("alice", "GetTask", { id: taskHex("c1") }))).toBe(-32001);
    // The standard shapes go through: an empty configuration, accepted modes that include ours, a null push config, no task id.
    const message = { ...base.message };
    delete (message as any).taskId;
    for (const [i, configuration] of [{}, { acceptedOutputModes: [] }, { acceptedOutputModes: ["text/plain", SEALED_MEDIA_TYPE] }, { acceptedOutputModes: ["*/*"] }, { acceptedOutputModes: ["application/*"] }, { taskPushNotificationConfig: null, historyLength: 0, returnImmediately: true }].entries()) {
      const id = `ok${i}`;
      const r = await w.rpc("alice", "SendMessage", { message: { ...w.msg("TASK", id, "alice", "bob").message }, configuration, tenant: w.T });
      expect(r.result?.task.id, JSON.stringify(configuration)).toBe(taskHex(id));
    }
    // The task id comes from the signed header when the request omits it, and must match it when it does not.
    const r = await w.rpc("alice", "SendMessage", { message: w.msg("TASK", "omitted", "alice", "bob").message });
    expect(r.result.task.id).toBe(taskHex("omitted"));
    expect(errCode(await send({ message: { ...w.msg("TASK", "x1", "alice", "bob").message, taskId: taskHex("other") } }, "x1"))).toBe(-32602);
    expect(errCode(await send({ message: { ...w.msg("TASK", "x2", "alice", "bob").message, extensions: ["https://x/ext"] } }, "x2"))).toBe(-32602);
    expect(errCode(await send({ message: { ...w.msg("TASK", "x3", "alice", "bob").message, referenceTaskIds: ["t"] } }, "x3"))).toBe(-32602);
    expect((await send({ message: { ...w.msg("TASK", "x4", "alice", "bob").message, extensions: [], referenceTaskIds: [], taskId: taskHex("x4"), contextId: "ctx" } }, "x4")).result).toBeDefined();
  });
});

describe("sealed parts", () => {
  it("accepts only opaque sealed envelopes and the routing hints", async () => {
    const w = world();
    const sealedOk = w.part("TASK", "p0", "alice", "bob");
    const m = (id: string, message: Record<string, unknown>) => ({ message: { ...w.msg("TASK", id, "alice", "bob").message, ...message } });
    const bad: [string, any][] = [
      ["text part", m("p1", { parts: [{ text: "CANARY-TEXT" }] })],
      ["data part", m("p2", { parts: [{ data: { a: 1 } }] })],
      ["url part", m("p3", { parts: [{ url: "https://x/f", mediaType: SEALED_MEDIA_TYPE }] })],
      ["filename", m("p4", { parts: [{ ...sealedOk, filename: "CANARY.txt" }] })],
      ["part metadata", m("p5", { parts: [{ ...sealedOk, metadata: { a: 1 } }] })],
      ["wrong media type", m("p6", { parts: [{ ...sealedOk, mediaType: "text/plain" }] })],
      ["no media type", m("p7", { parts: [{ raw: sealedOk.raw }] })],
      ["not an envelope", m("p8", { parts: [{ raw: "c2VhbGVk", mediaType: SEALED_MEDIA_TYPE }] })],
      ["not base64", m("p9", { parts: [{ raw: "not base64!", mediaType: SEALED_MEDIA_TYPE }] })],
      ["no parts", m("p10", { parts: [] })],
      ["parts not an array", m("p11", { parts: "x" })],
      ["two parts", m("p12", { parts: [sealedOk, sealedOk] })],
      ["part not an object", m("p13", { parts: ["x"] })],
      ["extra message field", m("p14", { text: "CANARY" })],
      ["extra params field", { ...m("p15", {}), extra: 1 }],
      ["free metadata", m("p16", { metadata: { note: "CANARY" } })],
      ["metadata not object", m("p17", { metadata: [] })],
      ["parley not object", m("p18", { metadata: { parley: 1 } })],
      ["free parley key", m("p19", { metadata: { parley: { note: "CANARY" } } })],
      ["no message", {}],
      ["message not object", { message: [] }],
      ["bad message id", m("p20", { messageId: "a/b" })],
      ["no message id", m("p21", { messageId: undefined })],
      ["agent role on a task", m("p22", { role: "ROLE_AGENT" })],
      ["no role", m("p23", { role: undefined })],
      ["context id the header does not carry", m("p24", { contextId: "other" })],
      ["task id the header does not carry", m("p25", { taskId: "tk" })],
    ];
    for (const [name, p] of bad) expect(errCode(await w.rpc("alice", "SendMessage", p)), name).toBe(-32602);
    expect(errCode(await w.rpc("alice", "SendMessage", w.msg("TASK", "p30", "alice", "bob")))).toBe(-32010); // well-formed, bob offline
  });

  it("holds the request to the signed header", async () => {
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    const t = async (name: string, p: any, code = -32602) => expect(errCode(await w.rpc("alice", "SendMessage", p)), name).toBe(code);
    const hint = (id: string, parley: Record<string, unknown>) => w.hinted(w.msg("TASK", id, "alice", "bob"), parley);
    // The sealed sender and tenant are the authenticated device and tenant.
    await t("sender is not the caller", w.msg("TASK", "h1", "alice", "bob", undefined, { header: { sender: "mallory" } }));
    await t("tenant is not the caller's", w.msg("TASK", "h2", "alice", "bob", undefined, { header: { tenant: "other" } }));
    await t("target is the caller", w.msg("TASK", "h3", "alice", "alice"));
    await t("target is not an id", w.msg("TASK", "h4", "alice", "a/b"));
    // The hints, when given, repeat the header.
    await t("hint names another kind", hint("h5", { kind: "STATUS" }));
    await t("hint REJECTED on a TASK", hint("h6", { kind: "REJECTED" }));
    await t("hint names another target", hint("h7", { to: "carol" }));
    await t("hint names another sequence number", hint("h8", { seq: 4 }));
    await t("hint kind is not a string", hint("h9", { kind: 7 }));
    await t("hint kind is a prototype property", hint("h10", { kind: "constructor" }));
    expect((await w.rpc("alice", "SendMessage", hint("h11", { kind: "TASK", to: "bob", seq: 0 }))).result).toBeDefined();
    // Nothing above reached the Task DO.
    for (const id of ["h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10"]) expect(errCode(await w.rpc("alice", "GetTask", { id: taskHex(id) })), id).toBe(-32001);
  });

  it("an error never repeats what the sender put in", async () => {
    const w = world();
    const r = await w.rpc("alice", "SendMessage", w.msg("TASK", "CANARY-TASK", "alice", "CANARY-TO"));
    expect(JSON.stringify(r)).not.toContain("CANARY");
    const q = await w.rpc("alice", "SendMessage", { message: { ...w.msg("TASK", "x", "alice", "bob").message, text: "CANARY", metadata: { parley: { kind: "CANARY" } } } });
    expect(JSON.stringify(q)).not.toContain("CANARY");
  });
});

describe("lifecycle over the transport", () => {
  it("runs a task: SUBMITTED, WORKING, INPUT_REQUIRED, a signed reply on the same task, COMPLETED", async () => {
    const w = world();
    const alice = await connect(w.T, "alice");
    const bob = await connect(w.T, "bob");
    const p = w.part("TASK", "tk", "alice", "bob");
    const made = await w.rpc("alice", "SendMessage", { message: { messageId: "m1", role: "ROLE_USER", parts: [p] } });
    expect(made.result.task).toMatchObject({ id: taskHex("tk"), status: { state: "TASK_STATE_SUBMITTED" } });
    expect(JSON.stringify(made)).not.toContain(p.raw); // the sender's own sealed message is not echoed back

    // The target receives the sealed part as the status message, from the caller.
    const first = await bob.event();
    expect(first.a2a).toBe("1.0");
    expect(first.task.status.state).toBe("TASK_STATE_SUBMITTED");
    expect(first.task.status.message).toMatchObject({ taskId: taskHex("tk"), contextId: "ctx", role: "ROLE_USER", parts: [p], metadata: { parley: { kind: "TASK", from: "alice" } } });

    const status = await w.bob("STATUS", "tk", 1);
    expect(status.result.task.status.state).toBe("TASK_STATE_WORKING");
    const s = await alice.event();
    expect(s.task.status).toMatchObject({ state: "TASK_STATE_WORKING", message: { role: "ROLE_AGENT", metadata: { parley: { kind: "STATUS", from: "bob", seq: 1 } } } });

    const q = await w.bob("INPUT_REQUIRED", "tk", 2);
    expect(q.result.task.status.state).toBe("TASK_STATE_INPUT_REQUIRED");
    expect((await alice.event()).task.status.state).toBe("TASK_STATE_INPUT_REQUIRED");
    expect(await w.state("tk")).toBe("TASK_STATE_INPUT_REQUIRED");

    const reply = await w.alice("REPLY", "tk", 1);
    expect(reply.result.task.status.state).toBe("TASK_STATE_WORKING");
    const r = await bob.event();
    expect(r.task.status).toMatchObject({ state: "TASK_STATE_WORKING", message: { role: "ROLE_USER", metadata: { parley: { kind: "REPLY", seq: 1 } } } });

    const done = await w.bob("RESULT", "tk", 3);
    expect(done.result.task.status.state).toBe("TASK_STATE_COMPLETED");
    expect((await alice.event()).task.status.state).toBe("TASK_STATE_COMPLETED");
    expect(await w.state("tk", "bob")).toBe("TASK_STATE_COMPLETED");
  });

  it("maps every target kind to its A2A state, REJECTED being an ERROR on the wire", async () => {
    for (const [kind, hint, state] of [["INPUT_REQUIRED", undefined, "INPUT_REQUIRED"], ["ERROR", undefined, "FAILED"], ["ERROR", "REJECTED", "REJECTED"], ["ERROR", "ERROR", "FAILED"], ["RESULT", undefined, "COMPLETED"], ["STATUS", undefined, "WORKING"]] as const) {
      const w = world();
      await connect(w.T, "alice");
      await connect(w.T, "bob");
      await w.task("tk");
      const r = await w.bob(kind, "tk", 1, hint);
      expect(r.result.task.status.state, `${kind} ${hint}`).toBe(STATE_NAME[state]);
    }
    // REJECTED is only a refusal of the task: it is not allowed once work has begun.
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    await w.task("tk");
    await w.bob("STATUS", "tk", 1);
    expect(errCode(await w.bob("ERROR", "tk", 2, "REJECTED"))).toBe(-32015);
  });

  it("moves a task only where the Task DO's state machine allows, from every state", async () => {
    const reach: Record<TaskState, (w: ReturnType<typeof world>, id: string) => Promise<number>> = {
      SUBMITTED: async () => 0,
      WORKING: async (w, id) => (await w.bob("STATUS", id, 1), 1),
      INPUT_REQUIRED: async (w, id) => (await w.bob("INPUT_REQUIRED", id, 1), 1),
      COMPLETED: async (w, id) => (await w.bob("RESULT", id, 1), 1),
      FAILED: async (w, id) => (await w.bob("ERROR", id, 1), 1),
      REJECTED: async (w, id) => (await w.bob("ERROR", id, 1, "REJECTED"), 1),
      CANCELED: async (w, id) => (await w.cancel(id, 1), 0),
    };
    // Each probe: how to send it, and the state it asks for.
    const probes: [string, TaskState, (w: ReturnType<typeof world>, id: string, tseq: number) => Promise<any>][] = [
      ["STATUS", "WORKING", (w, id, s) => w.bob("STATUS", id, s + 1)],
      ["INPUT_REQUIRED", "INPUT_REQUIRED", (w, id, s) => w.bob("INPUT_REQUIRED", id, s + 1)],
      ["RESULT", "COMPLETED", (w, id, s) => w.bob("RESULT", id, s + 1)],
      ["ERROR", "FAILED", (w, id, s) => w.bob("ERROR", id, s + 1)],
      ["REJECTED", "REJECTED", (w, id, s) => w.bob("ERROR", id, s + 1, "REJECTED")],
      ["REPLY", "WORKING", (w, id) => w.alice("REPLY", id, 1)],
      ["CANCEL", "CANCELED", async (w, id, s) => w.cancel(id, s === 0 ? 1 : 2)],
    ];
    // One pair of tunnels, one task per (state, event): connections and storage writes are the slow part on some runners.
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    let k = 0;
    for (const from of Object.keys(reach) as TaskState[]) {
      for (const [name, to, probe] of probes) {
        const id = `x${++k}`;
        await w.task(id);
        const seq = await reach[from](w, id);
        expect(await w.state(id), `reached ${from}`).toBe(STATE_NAME[from]);
        const allowed = name === "REPLY" ? from === "INPUT_REQUIRED" : NEXT[from].includes(to);
        const r = await probe(w, id, seq);
        expect(r.result !== undefined, `${name} from ${from}: ${JSON.stringify(r.error)}`).toBe(allowed);
        expect(await w.state(id), `${name} from ${from}`).toBe(STATE_NAME[allowed ? to : from]);
        if (!allowed) expect([-32015, -32002], `${name} from ${from}`).toContain(errCode(r));
      }
    }
  }, LONG_WALK_MS);

  it("a target that went offline closes the task instead of leaving it to expire", async () => {
    const w = world();
    await connect(w.T, "alice");
    expect(errCode(await w.task("tk"))).toBe(-32010);
    expect(await w.state("tk")).toBe("TASK_STATE_CANCELED");
    // The id is spent; the sender starts a new task with a fresh prekey.
    expect(errCode(await w.task("tk"))).toBe(-32012);
    await connect(w.T, "bob");
    expect((await w.task("tk2")).result.task.status.state).toBe("TASK_STATE_SUBMITTED");
  });

  it("a caller that is gone fails the task when the target reports (Strict)", async () => {
    const w = world();
    await setRetention(w.T, { mode: "strict" });
    await connect(w.T, "bob");
    // Alice has no tunnel, but the task exists: create it through a connected alice, then drop her.
    const alice = await connect(w.T, "alice");
    await w.task("tk");
    alice.ws.close(1000, "bye");
    await gone(w.T, "alice");
    const r = await w.bob("STATUS", "tk", 1);
    expect(errCode(r)).toBe(-32010);
    const t = await w.rpc("bob", "GetTask", { id: taskHex("tk") });
    expect(t.result.status.state).toBe("TASK_STATE_FAILED");
    expect(t.result.metadata.parley.reason).toBe("disconnected");
    expect(await heldFor(w.T, "tk")).toEqual([]); // nothing was stored for the lost result
  });

  it("a reply the target never received fails the task instead of leaving it waiting", async () => {
    const w = world();
    await connect(w.T, "alice");
    const bob = await connect(w.T, "bob");
    await w.task("tk");
    await w.bob("INPUT_REQUIRED", "tk", 1);
    bob.ws.close(1000, "bye");
    await gone(w.T, "bob");
    expect(errCode(await w.alice("REPLY", "tk", 1))).toBe(-32010);
    expect(await w.state("tk")).toBe("TASK_STATE_FAILED");
  });

  it("refuses out-of-order, replayed, wrong-side and late messages", async () => {
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    await w.task("tk");
    const st = (seq: number, kind: SignedKind = "STATUS") => w.bob(kind, "tk", seq);
    expect((await st(2)).result).toBeDefined();
    expect(errCode(await st(2))).toBe(-32011); // replay
    expect(errCode(await st(1))).toBe(-32011); // reorder
    // The sequence number is the signed one; a request cannot choose another.
    expect(errCode(await w.rpc("bob", "SendMessage", w.hinted(w.msg("STATUS", "tk", "bob", "alice", 5), { seq: 6 })))).toBe(-32602);
    // Each side may send only its own kinds, to the other side.
    expect(errCode(await w.rpc("bob", "SendMessage", w.msg("STATUS", "tk", "bob", "alice", 5, { message: { role: "ROLE_USER" } })))).toBe(-32602); // wrong role
    expect(errCode(await w.rpc("bob", "SendMessage", w.msg("REPLY", "tk", "bob", "alice", 5)))).toBe(-32602);
    expect(errCode(await w.rpc("bob", "SendMessage", w.msg("TASK", "tk", "bob", "alice")))).toBe(-32012); // a new task under a taken id
    expect(errCode(await w.rpc("bob", "SendMessage", w.msg("CANCEL", "tk", "bob", "alice", 5)))).toBe(-32602);
    expect(errCode(await w.rpc("alice", "SendMessage", w.msg("RESULT", "tk", "alice", "bob", 5)))).toBe(-32602);
    expect(errCode(await w.rpc("alice", "SendMessage", w.msg("CANCEL", "tk", "alice", "bob", 5)))).toBe(-32602); // cancel has its own method
    expect(errCode(await w.rpc("bob", "SendMessage", w.msg("STATUS", "tk", "bob", "carol", 5)))).toBe(-32602); // not to the caller
    expect(errCode(await w.rpc("alice", "SendMessage", w.msg("REPLY", "tk", "alice", "carol", 1)))).toBe(-32602); // not to the target
    // A reply needs a question.
    expect(errCode(await w.alice("REPLY", "tk", 1))).toBe(-32015);
    expect(errCode(await w.task("tk"))).toBe(-32012);
    // After a terminal state nothing is accepted.
    expect((await st(3, "RESULT")).result).toBeDefined();
    expect(errCode(await st(4))).toBe(-32015);
    // About 25 requests through the Worker and several Durable Objects: seconds on Windows CI storage (41 s on one noisy run), so it
    // gets the same explicit limit as the other long walks in this file rather than a higher global one.
  }, LONG_WALK_MS);

  it("a third device, another tenant and a missing task all look like no task", async () => {
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    await w.task("tk");
    expect(errCode(await w.rpc("mallory", "SendMessage", w.msg("STATUS", "tk", "mallory", "alice", 1)))).toBe(-32001);
    expect(errCode(await w.rpc("mallory", "GetTask", { id: taskHex("tk") }))).toBe(-32001);
    expect(errCode(await w.cancel("tk", 1, "mallory"))).toBe(-32001);
    expect(errCode(await w.rpc("bob", "GetTask", { id: taskHex("nope") }))).toBe(-32001);
    expect(errCode(await w.bob("STATUS", "nope", 1))).toBe(-32001);
    expect(errCode(await w.cancel("nope", 1, "bob", "alice"))).toBe(-32001);
    const other = fresh();
    const r = await gw("https://gw/a2a", { method: "POST", headers: other.bearer("alice"), body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "GetTask", params: { id: taskHex("tk") } }) });
    expect(errCode(await r.json())).toBe(-32001);
    for (const id of ["a/b", "tk", "nope", taskHex("tk").toUpperCase(), taskHex("tk") + "0", taskHex("tk").slice(1), "CANARY-id"]) {
      expect(errCode(await w.rpc("alice", "GetTask", { id })), id).toBe(-32602);
      expect(errCode(await w.rpc("alice", "CancelTask", { id, metadata: { parley: { messageId: "c1", parts: [w.part("CANCEL", "tk", "alice", "bob", 1)] } } })), id).toBe(-32602);
    }
    expect(errCode(await w.rpc("alice", "GetTask", { id: "tk", extra: 1 }))).toBe(-32602);
    expect((await w.rpc("alice", "GetTask", { id: taskHex("tk"), historyLength: 0, tenant: w.T })).result).toBeDefined();
  });

  it("the biggest bucket fits one frame, and a header cannot make a deliverable part too big", async () => {
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    const r = await w.rpc("alice", "SendMessage", w.msg("TASK", "big", "alice", "bob", undefined, { bucket: MAX_BUCKET }));
    expect(r.result.task.status.state).toBe("TASK_STATE_SUBMITTED");
    // One bucket larger is over the request cap, refused unparsed.
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "SendMessage", params: w.msg("TASK", "bigger", "alice", "bob", undefined, { bucket: MAX_BUCKET * 2 }) });
    expect((await gw("https://gw/a2a", { method: "POST", headers: w.bearer("alice"), body })).status).toBe(413);
    // Under the cap but not a bucket: refused as malformed.
    const odd = { raw: b64(encodeWire({ header: header("TASK", { tenant: w.T, sender: "alice", target: "bob", task: taskBytes("odd") }), ctLen: 600_000 })), mediaType: SEALED_MEDIA_TYPE };
    expect(errCode(await w.rpc("alice", "SendMessage", { message: { messageId: "m1", role: "ROLE_USER", parts: [odd] } }))).toBe(-32602);
    expect(errCode(await w.rpc("alice", "GetTask", { id: taskHex("odd") }))).toBe(-32001);
  });
});

async function gone(T: string, device: string) {
  for (let i = 0; i < 100; i++) {
    if (!(await (env.DEVICE.get(env.DEVICE.idFromName(`${T}:${device}`)) as any).status()).connected) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("the tunnel did not close");
}

it("the gateway stores no part bytes: task storage holds metadata only", async () => {
  const w = world();
  await connect(w.T, "alice");
  await connect(w.T, "bob");
  const canary = new TextEncoder().encode("CANARY-CONTENT-7f3a"); // sealed bytes the gateway must never keep
  const over = { context: "CANARY-CTX-7f3a", keyId: "CANARY-KEY-7f3a" };
  const sent = (kind: SignedKind, from: string, to: string, seq: number, dev: string) => {
    const message = { messageId: "m1", role: ROLE[kind] ?? "ROLE_AGENT", parts: [w.part(kind, "tk", from, to, seq, over, 4096, canary)] };
    return w.rpc(dev, "SendMessage", { message });
  };
  expect((await sent("TASK", "alice", "bob", 0, "alice")).result).toBeDefined();
  expect((await sent("RESULT", "bob", "alice", 1, "bob")).result).toBeDefined();
  const dump = JSON.stringify(
    await runInDurableObject(env.TASK.get(env.TASK.idFromName(`${w.T}:${taskHex("tk")}`)), async (_, ctx) => Object.fromEntries(await ctx.storage.list())),
  );
  expect(dump).toContain('"state":"COMPLETED"');
  expect(dump).not.toContain("CANARY");
  expect(dump).not.toContain(btoa("CANARY-CONTENT"));
});

// Strict: the gateway relays results, status, questions and errors and keeps none of them. Every kind
// carries a canary in its sealed bytes; afterward no Durable Object of the tenant holds a trace of it.
it("Strict leaves no canary in any storage after completion, for an online and an offline caller", async () => {
  const dumpAll = async (w: ReturnType<typeof world>, tasks: string[]) => {
    const out: unknown[] = [];
    const stubs = [
      ...tasks.map((t) => env.TASK.get(env.TASK.idFromName(`${w.T}:${taskHex(t)}`))),
      env.DEVICE.get(env.DEVICE.idFromName(`${w.T}:alice`)),
      env.DEVICE.get(env.DEVICE.idFromName(`${w.T}:bob`)),
      env.TENANT.get(env.TENANT.idFromName(w.T)),
    ];
    for (const st of stubs) out.push(await runInDurableObject(st, async (_, ctx) => Object.fromEntries(await ctx.storage.list())));
    return JSON.stringify(out);
  };
  const canary = (k: string) => new TextEncoder().encode(`CANARY-${k}-9c1e`);
  const w = world();
  const alice = await connect(w.T, "alice");
  await connect(w.T, "bob");
  const send = (kind: SignedKind, from: string, to: string, seq: number, id: string, hint?: string) =>
    w.rpc(from, "SendMessage", { message: { messageId: `m${seq}`, role: ROLE[kind] ?? "ROLE_AGENT", parts: [w.part(kind, id, from, to, seq, { context: "CANARY-FILE-9c1e.txt" }, 4096, canary(kind))] }, ...(hint ? { metadata: { parley: { hint } } } : {}) });
  expect((await send("TASK", "alice", "bob", 0, "ok")).result).toBeDefined();
  for (const [k, seq] of [["STATUS", 1], ["INPUT_REQUIRED", 2]] as const) expect((await send(k, "bob", "alice", seq, "ok")).result).toBeDefined();
  expect((await send("REPLY", "alice", "bob", 1, "ok")).result).toBeDefined();
  expect((await send("RESULT", "bob", "alice", 3, "ok")).result.task.status.state).toBe("TASK_STATE_COMPLETED");
  expect((await send("TASK", "alice", "bob", 0, "bad")).result).toBeDefined();
  expect((await send("ERROR", "bob", "alice", 1, "bad")).result.task.status.state).toBe("TASK_STATE_FAILED");
  // An offline caller: refused, not queued.
  expect((await send("TASK", "alice", "bob", 0, "off")).result).toBeDefined();
  alice.ws.close(1000, "bye");
  await gone(w.T, "alice");
  expect(errCode(await send("RESULT", "bob", "alice", 1, "off"))).toBe(-32010);
  const dump = await dumpAll(w, ["ok", "bad", "off"]);
  expect(dump).toContain("COMPLETED");
  for (const k of ["TASK", "STATUS", "INPUT_REQUIRED", "REPLY", "RESULT", "ERROR"]) {
    expect(dump).not.toContain(`CANARY-${k}`);
    expect(dump).not.toContain(btoa(`CANARY-${k}`).slice(0, 16));
  }
  expect(dump).not.toContain("CANARY-FILE");
  expect(dump).not.toContain('"q:');
});

describe("cancel", () => {
  it("cancels with a sealed, sequenced message that the target receives", async () => {
    const w = world();
    await connect(w.T, "alice");
    const bob = await connect(w.T, "bob");
    await w.task("tk");
    await bob.event();
    const r = await w.cancel("tk", 1);
    expect(r.result.status.state).toBe("TASK_STATE_CANCELED");
    expect(r.result.metadata.parley.reason).toBe("canceled");
    const e = await bob.event();
    expect(e.task.status).toMatchObject({ state: "TASK_STATE_CANCELED", message: { role: "ROLE_USER", metadata: { parley: { kind: "CANCEL", from: "alice", seq: 1 } } } });
    expect(e.task.status.message.parts).toEqual(w.cancelParams("tk", 1).metadata.parley.parts);
    // Late traffic from either side is refused.
    expect(errCode(await w.bob("RESULT", "tk", 1))).toBe(-32015);
    expect(errCode(await w.cancel("tk", 2))).toBe(-32002);
  });

  it("still cancels when the target is offline", async () => {
    const w = world();
    await connect(w.T, "alice");
    const bob = await connect(w.T, "bob");
    await w.task("tk");
    bob.ws.close(1000, "bye");
    await gone(w.T, "bob");
    expect((await w.cancel("tk", 1)).result.status.state).toBe("TASK_STATE_CANCELED");
  });

  it("only the caller cancels, with a proper signed message", async () => {
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    await w.task("tk");
    expect(errCode(await w.cancel("tk", 1, "bob", "alice"))).toBe(-32013);
    expect(errCode(await w.cancel("tk", 0))).toBe(-32602); // a CANCEL envelope has seq 0 only if forged: the header rules refuse it
    const good = w.cancelParams("tk", 1);
    const part = good.metadata.parley.parts[0]!;
    const withParts = (parts: unknown, extra: Record<string, unknown> = {}) => ({ id: good.id, metadata: { parley: { messageId: "c1", parts, ...extra } } });
    for (const [name, p] of [
      ["a bare A2A cancel cannot be authenticated by the target", { id: good.id }],
      ["no parley metadata", { id: good.id, metadata: {} }],
      ["no parts", { id: good.id, metadata: { parley: { messageId: "c1" } } }],
      ["a text part", withParts([{ text: "x" }])],
      ["two parts", withParts([part, part])],
      ["no message id", { id: good.id, metadata: { parley: { parts: [part] } } }],
      ["a free key", withParts([part], { note: "x" })],
      ["another metadata key", { id: good.id, metadata: { other: 1 } }],
      ["parley not an object", { id: good.id, metadata: { parley: [] } }],
      ["a bad id", { ...withParts([part]), id: "a/b" }],
      ["an extra field", { ...good, extra: 1 }],
      ["a task id the envelope does not carry", { ...withParts([part]), id: taskHex("other") }],
      ["a sequence number the envelope does not carry", withParts([part], { seq: 9 })],
      ["another tenant's tenant field", { ...good, tenant: "other" }],
      ["a STATUS envelope", withParts([w.part("STATUS", "tk", "alice", "bob", 1)])],
      ["an envelope from another sender", withParts([w.part("CANCEL", "tk", "mallory", "bob", 1)])],
      ["an envelope for another tenant", withParts([w.part("CANCEL", "tk", "alice", "bob", 1, { tenant: "other" })])],
      ["an envelope for another target", withParts([w.part("CANCEL", "tk", "alice", "carol", 1)])],
    ] as [string, any][]) expect(errCode(await w.rpc("alice", "CancelTask", p)), name).toBe(-32602);
    expect(await w.state("tk")).toBe("TASK_STATE_SUBMITTED");
    expect((await w.rpc("alice", "CancelTask", withParts([part], { seq: 1 }))).result.status.state).toBe("TASK_STATE_CANCELED");
  });

  it("refuses a replayed or reordered cancel", async () => {
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    await w.task("tk");
    await w.alice("REPLY", "tk", 3).then((r) => expect(errCode(r)).toBe(-32015)); // consumes nothing: refused by state before seq
    await w.bob("INPUT_REQUIRED", "tk", 1);
    expect((await w.alice("REPLY", "tk", 5)).result).toBeDefined();
    expect(errCode(await w.cancel("tk", 5))).toBe(-32011);
    expect(errCode(await w.cancel("tk", 4))).toBe(-32011);
    expect((await w.cancel("tk", 6)).result).toBeDefined();
  });
});

// Keeps the envelope type numbers visible to the type checker.
void SIGNED_TYPE;


const setRetention = async (T: string, body: unknown) => {
  const { secret } = await env.TENANT.get(env.TENANT.idFromName(T)).createSession("admin@example.test", "admin");
  const r = await SELF.fetch("https://gw/v1/admin/retention/put", { method: "POST", headers: { Authorization: `Bearer ps_${T}.${secret}` }, body: JSON.stringify(body) });
  expect(r.status).toBe(200);
};
const heldFor = (T: string, id: string) =>
  runInDurableObject(env.TASK.get(env.TASK.idFromName(`${T}:${taskHex(id)}`)), async (_, ctx) => [...(await ctx.storage.list({ prefix: "q:" })).keys()]);

describe("retention modes over the transport", () => {
  afterEach(() => vi.useRealTimers());
  // A task from alice to bob, with alice then disconnected.
  async function offlineCaller(w: ReturnType<typeof world>, id = "tk") {
    const alice = await connect(w.T, "alice");
    await connect(w.T, "bob");
    await w.task(id);
    alice.ws.close(1000, "bye");
    await gone(w.T, "alice");
  }

  it("Queued holds a result for a caller that was offline and delivers it on reconnect", async () => {
    const w = world();
    await setRetention(w.T, { mode: "queued" });
    await offlineCaller(w);
    const r = await w.bob("STATUS", "tk", 1);
    expect(r.result.task.status.state).toBe("TASK_STATE_WORKING"); // accepted, not failed
    expect((await w.bob("RESULT", "tk", 2)).result.task.status.state).toBe("TASK_STATE_COMPLETED");
    expect(await heldFor(w.T, "tk")).toHaveLength(2);
    const alice = await connect(w.T, "alice");
    const [a, b] = [await alice.event(), await alice.event()];
    expect(a.task.status.message.metadata.parley).toMatchObject({ kind: "STATUS", seq: 1 });
    expect(b.task.status.message.metadata.parley).toMatchObject({ kind: "RESULT", seq: 2 });
    expect(await heldFor(w.T, "tk")).toHaveLength(2); // until acknowledged
    expect((await w.rpc("alice", "GetTask", { id: taskHex("tk") })).result.metadata.parley.ciphertext_deleted_at).toBeUndefined();
    alice.ws.send(JSON.stringify({ t: "ack", seq: 2 }));
    for (let i = 0; i < 200 && (await heldFor(w.T, "tk")).length; i++) await new Promise((r) => setTimeout(r, 10));
    expect(await heldFor(w.T, "tk")).toEqual([]);
    const t = (await w.rpc("alice", "GetTask", { id: taskHex("tk") })).result;
    expect(t.status.state).toBe("TASK_STATE_COMPLETED");
    expect(t.metadata.parley.ciphertext_deleted_at).toBeGreaterThan(0);
  });

  it("Queued deletes a held result at the tenant's TTL if the caller never comes back", async () => {
    const w = world();
    await setRetention(w.T, { mode: "queued", queue_ttl_ms: QUEUE_TTL_MIN_MS });
    await offlineCaller(w);
    await w.bob("RESULT", "tk", 1);
    expect(await heldFor(w.T, "tk")).toHaveLength(1);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + QUEUE_TTL_MIN_MS);
    expect(await runDurableObjectAlarm(env.TASK.get(env.TASK.idFromName(`${w.T}:${taskHex("tk")}`)))).toBe(true);
    expect(await heldFor(w.T, "tk")).toEqual([]);
    vi.useRealTimers();
    const alice = await connect(w.T, "alice"); // nothing is left to deliver
    expect(alice.pending()).toBe(0);
    expect((await w.rpc("alice", "GetTask", { id: taskHex("tk") })).result.metadata.parley.ciphertext_deleted_at).toBeGreaterThan(0);
  });

  it("Strict stores nothing: the task fails when the caller is not connected", async () => {
    const w = world();
    await setRetention(w.T, { mode: "strict" });
    await offlineCaller(w);
    expect(errCode(await w.bob("STATUS", "tk", 1))).toBe(-32010);
    expect(await w.state("tk", "bob")).toBe("TASK_STATE_FAILED");
    expect(await heldFor(w.T, "tk")).toEqual([]);
  });

  it("is Strict until the admin chooses Queued: nothing is held for an offline caller", async () => {
    const w = world();
    await offlineCaller(w);
    expect(errCode(await w.bob("RESULT", "tk", 1))).toBe(-32010);
    expect(await heldFor(w.T, "tk")).toEqual([]);
  });

  it("a task keeps the mode it was created under when the admin changes it", async () => {
    const w = world();
    await setRetention(w.T, { mode: "queued" });
    await offlineCaller(w, "q1"); // created under Queued
    await setRetention(w.T, { mode: "strict" });
    expect((await w.bob("RESULT", "q1", 1)).result).toBeDefined();
    expect(await heldFor(w.T, "q1")).toHaveLength(1);
    const alice = await connect(w.T, "alice");
    await w.task("s1"); // created under Strict
    alice.ws.close(1000, "bye");
    await gone(w.T, "alice");
    expect(errCode(await w.bob("RESULT", "s1", 1))).toBe(-32010);
    expect(await heldFor(w.T, "s1")).toEqual([]);
  });

  it("never holds what the caller sent, so a reply to an offline target still fails the task", async () => {
    const w = world();
    await connect(w.T, "alice");
    const bob = await connect(w.T, "bob");
    await w.task("tk");
    await w.bob("INPUT_REQUIRED", "tk", 1);
    bob.ws.close(1000, "bye");
    await gone(w.T, "bob");
    expect(errCode(await w.alice("REPLY", "tk", 1))).toBe(-32010);
    expect(await heldFor(w.T, "tk")).toEqual([]);
  });

  it("fails the task when the queue is full", async () => {
    const w = world();
    await setRetention(w.T, { mode: "queued" });
    await offlineCaller(w);
    for (let i = 1; i <= MAX_QUEUED; i++) expect((await w.bob("STATUS", "tk", i)).result).toBeDefined();
    expect(errCode(await w.bob("STATUS", "tk", MAX_QUEUED + 1))).toBe(-32010);
    expect(await w.state("tk", "bob")).toBe("TASK_STATE_FAILED");
  });

  it("fails the task when the caller's device cannot note any more tasks", async () => {
    const w = world();
    await setRetention(w.T, { mode: "queued" });
    await offlineCaller(w);
    await runInDurableObject(env.DEVICE.get(env.DEVICE.idFromName(`${w.T}:alice`)), (_, ctx) =>
      ctx.storage.put("held", Array.from({ length: MAX_HELD }, (_, i) => ({ tenant: w.T, device: "alice", task: `other${i}`, until: Date.now() + 60_000 }))),
    );
    expect(errCode(await w.bob("STATUS", "tk", 1))).toBe(-32010);
    expect(await w.state("tk", "bob")).toBe("TASK_STATE_FAILED");
    expect(await heldFor(w.T, "tk")).toEqual([]);
  });

  it("holds only the sealed envelope: no readable field reaches storage", async () => {
    const w = world();
    await setRetention(w.T, { mode: "queued" });
    await offlineCaller(w);
    await w.bob("RESULT", "tk", 1);
    const all = await runInDurableObject(env.TASK.get(env.TASK.idFromName(`${w.T}:${taskHex("tk")}`)), async (_, ctx) => Object.fromEntries(await ctx.storage.list()));
    const held = JSON.parse((all["q:000000000001"] as { body: string }).body);
    expect(Object.keys(held.task.status.message.parts[0]).sort()).toEqual(["mediaType", "raw"]);
    expect(held.task.status.message.metadata.parley).toEqual({ kind: "RESULT", from: "bob", seq: 1 });
  });
});
