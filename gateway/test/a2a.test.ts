// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { MAX_FRAME_BYTES } from "../src/protocol";
import { MAX_REQUEST_BYTES, SEALED_MEDIA_TYPE, STATE_NAME } from "../src/a2a";

// Each test gets its own tenant, so devices and tasks never collide.
let n = 0;
const fresh = () => {
  const T = `t${++n}`;
  return { T, bearer: (d: string) => ({ Authorization: `Bearer dev:${T}:${d}` }) };
};

const sealed = (s = "c2VhbGVk") => ({ raw: s, mediaType: SEALED_MEDIA_TYPE });

async function connect(T: string, device: string) {
  const res = await SELF.fetch("https://gw/v1/connect", { headers: { Upgrade: "websocket", Authorization: `Bearer dev:${T}:${device}` } });
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

function world() {
  const { T, bearer } = fresh();
  const rpc = async (device: string, method: string, params: unknown, id: unknown = 1) => {
    const r = await SELF.fetch("https://gw/a2a", { method: "POST", headers: bearer(device), body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) });
    expect(r.status).toBe(200);
    return (await r.json()) as any;
  };
  const msg = (taskId: string, role: string, kind: string, extra: Record<string, unknown> = {}, parts: unknown = [sealed()]) => ({
    message: { messageId: `m${++n}`, taskId, role, parts, metadata: { parley: { kind, ...extra } } },
  });
  const task = (id: string, from = "alice", to = "bob") => rpc(from, "SendMessage", msg(id, "ROLE_USER", "TASK", { to }));
  const state = async (id: string, dev = "alice") => (await rpc(dev, "GetTask", { id })).result.task.status.state;
  return { T, bearer, rpc, msg, task, state };
}

const errCode = (r: any) => r.error?.code;

describe("agent card and endpoint", () => {
  it("serves the card at the well-known path with the transport facts", async () => {
    const r = await SELF.fetch("https://gw/.well-known/agent-card.json");
    expect(r.status).toBe(200);
    const c: any = await r.json();
    expect(c.supportedInterfaces).toEqual([{ url: "https://gw/a2a", protocolBinding: "JSONRPC", protocolVersion: "1.0" }]);
    expect(c.capabilities).toEqual({ streaming: false, pushNotifications: false });
    expect(c.defaultInputModes).toEqual([SEALED_MEDIA_TYPE]);
    expect((await SELF.fetch("https://gw/.well-known/agent-card.json", { method: "POST" })).status).toBe(405);
  });

  it("needs a device identity and a POST, and bounds the body", async () => {
    const { bearer } = fresh();
    expect((await SELF.fetch("https://gw/a2a", { method: "POST", body: "{}" })).status).toBe(401);
    expect((await SELF.fetch("https://gw/a2a", { headers: bearer("a") })).status).toBe(405);
    const big = "x".repeat(MAX_REQUEST_BYTES + 1);
    expect((await SELF.fetch("https://gw/a2a", { method: "POST", headers: bearer("a"), body: big })).status).toBe(413);
    const lie = await SELF.fetch("https://gw/a2a", { method: "POST", headers: { ...bearer("a"), "content-length": String(MAX_REQUEST_BYTES + 1) }, body: "{}" });
    expect(lie.status).toBe(413);
    // Multi-byte text is measured in bytes, not characters.
    const wide = "é".repeat(MAX_REQUEST_BYTES / 2 + 1);
    expect(wide.length).toBeLessThanOrEqual(MAX_REQUEST_BYTES);
    expect((await SELF.fetch("https://gw/a2a", { method: "POST", headers: bearer("a"), body: wide })).status).toBe(413);
  });

  it("answers malformed JSON-RPC with the standard errors and never echoes input", async () => {
    const { bearer } = fresh();
    const post = async (body: string) => (await (await SELF.fetch("https://gw/a2a", { method: "POST", headers: bearer("a"), body })).json()) as any;
    expect(errCode(await post("{nope"))).toBe(-32700);
    for (const b of ['[]', '"x"', '{"jsonrpc":"1.0","method":"GetTask"}', '{"jsonrpc":"2.0"}', '{"jsonrpc":"2.0","method":"GetTask","id":{}}', '{"jsonrpc":"2.0","method":"GetTask","id":true}']) {
      expect(errCode(await post(b)), b).toBe(-32600);
    }
    expect(errCode(await post('{"jsonrpc":"2.0","method":"GetTask","id":1}'))).toBe(-32602);
    expect(errCode(await post('{"jsonrpc":"2.0","method":"GetTask","id":1,"params":[]}'))).toBe(-32602);
    const r = await post('{"jsonrpc":"2.0","method":"CANARY-METHOD","id":"CANARY-ID","params":{}}');
    expect(errCode(r)).toBe(-32601);
    expect(r.id).toBe("CANARY-ID");
    expect(JSON.stringify(r.error)).not.toContain("CANARY");
    const nullId = await post('{"jsonrpc":"2.0","method":"GetTask","id":null,"params":{}}');
    expect(nullId.id).toBeNull();
  });

  it("declines what the MVP does not offer", async () => {
    const { rpc } = world();
    for (const m of ["ListTasks", "SendStreamingMessage", "SubscribeToTask", "GetExtendedAgentCard"]) expect(errCode(await rpc("a", m, {})), m).toBe(-32004);
    for (const m of ["CreateTaskPushNotificationConfig", "GetTaskPushNotificationConfig", "ListTaskPushNotificationConfigs", "DeleteTaskPushNotificationConfig"]) {
      expect(errCode(await rpc("a", m, {})), m).toBe(-32003);
    }
  });
});

describe("sealed parts", () => {
  it("accepts only opaque sealed parts and the routing hints", async () => {
    const { rpc, msg } = world();
    const ok = (extra?: Record<string, unknown>) => msg("tk1", "ROLE_USER", "TASK", { to: "bob", ...extra });
    const bad: [string, any][] = [
      ["text part", msg("x1", "ROLE_USER", "TASK", { to: "bob" }, [{ text: "CANARY-TEXT" }])],
      ["data part", msg("x2", "ROLE_USER", "TASK", { to: "bob" }, [{ data: { a: 1 } }])],
      ["url part", msg("x3", "ROLE_USER", "TASK", { to: "bob" }, [{ url: "https://x/f", mediaType: SEALED_MEDIA_TYPE }])],
      ["filename", msg("x4", "ROLE_USER", "TASK", { to: "bob" }, [{ ...sealed(), filename: "CANARY.txt" }])],
      ["part metadata", msg("x5", "ROLE_USER", "TASK", { to: "bob" }, [{ ...sealed(), metadata: { a: 1 } }])],
      ["wrong media type", msg("x6", "ROLE_USER", "TASK", { to: "bob" }, [{ raw: "c2VhbGVk", mediaType: "text/plain" }])],
      ["no media type", msg("x7", "ROLE_USER", "TASK", { to: "bob" }, [{ raw: "c2VhbGVk" }])],
      ["not base64", msg("x8", "ROLE_USER", "TASK", { to: "bob" }, [sealed("not base64!")])],
      ["bad padding", msg("x9", "ROLE_USER", "TASK", { to: "bob" }, [sealed("YQ=")])],
      ["short", msg("x10", "ROLE_USER", "TASK", { to: "bob" }, [sealed("YWJ")])],
      ["empty raw", msg("x11", "ROLE_USER", "TASK", { to: "bob" }, [sealed("")])],
      ["non-string raw", msg("x12", "ROLE_USER", "TASK", { to: "bob" }, [{ raw: 5, mediaType: SEALED_MEDIA_TYPE }])],
      ["no parts", msg("x13", "ROLE_USER", "TASK", { to: "bob" }, [])],
      ["parts not an array", msg("x14", "ROLE_USER", "TASK", { to: "bob" }, "x")],
      ["too many parts", msg("x15", "ROLE_USER", "TASK", { to: "bob" }, Array(9).fill(sealed()))],
      ["part not an object", msg("x16", "ROLE_USER", "TASK", { to: "bob" }, ["x"])],
      ["extra message field", { message: { ...msg("x17", "ROLE_USER", "TASK", { to: "bob" }).message, text: "CANARY" } }],
      ["extra params field", { ...msg("x18", "ROLE_USER", "TASK", { to: "bob" }), extra: 1 }],
      ["free metadata", { message: { ...msg("x19", "ROLE_USER", "TASK", { to: "bob" }).message, metadata: { note: "CANARY" } } }],
      ["metadata not object", { message: { ...msg("x20", "ROLE_USER", "TASK", { to: "bob" }).message, metadata: [] } }],
      ["parley not object", { message: { ...msg("x21", "ROLE_USER", "TASK", { to: "bob" }).message, metadata: { parley: 1 } } }],
      ["free parley key", msg("x22", "ROLE_USER", "TASK", { to: "bob", note: "CANARY" })],
      ["no kind", { message: { ...msg("x23", "ROLE_USER", "TASK").message, metadata: { parley: { to: "bob" } } } }],
      ["no message", {}],
      ["message not object", { message: [] }],
      ["bad message id", { message: { ...msg("x24", "ROLE_USER", "TASK", { to: "bob" }).message, messageId: "a/b" } }],
      ["bad task id", msg("a/b", "ROLE_USER", "TASK", { to: "bob" })],
      ["no task id", { message: { ...msg("x25", "ROLE_USER", "TASK", { to: "bob" }).message, taskId: undefined } }],
      ["bad context id", { message: { ...msg("x26", "ROLE_USER", "TASK", { to: "bob" }).message, contextId: "a b" } }],
      ["no target", msg("x27", "ROLE_USER", "TASK")],
      ["bad target", msg("x28", "ROLE_USER", "TASK", { to: "a/b" })],
      ["target is the caller", msg("x29", "ROLE_USER", "TASK", { to: "alice" })],
      ["agent role on a task", msg("x30", "ROLE_AGENT", "TASK", { to: "bob" })],
      ["seq on a task", msg("x31", "ROLE_USER", "TASK", { to: "bob", seq: 1 })],
    ];
    for (const [name, p] of bad) expect(errCode(await rpc("alice", "SendMessage", p)), name).toBe(-32602);
    expect(errCode(await rpc("alice", "SendMessage", ok({ to: "bob" })))).toBe(-32010); // well-formed, bob offline
  });

  it("an error never repeats what the sender put in", async () => {
    const { rpc, msg } = world();
    const r = await rpc("alice", "SendMessage", msg("CANARY-TASK", "ROLE_USER", "TASK", { to: "CANARY/TO" }));
    expect(JSON.stringify(r)).not.toContain("CANARY");
  });
});

describe("lifecycle over the transport", () => {
  it("runs a task: SUBMITTED, WORKING, INPUT_REQUIRED, a reply on the same task, COMPLETED", async () => {
    const w = world();
    const alice = await connect(w.T, "alice");
    const bob = await connect(w.T, "bob");
    const made = await w.rpc("alice", "SendMessage", w.msg("tk", "ROLE_USER", "TASK", { to: "bob" }, [sealed("QUFB"), sealed("QkJC")]));
    expect(made.result.task).toMatchObject({ id: "tk", status: { state: "TASK_STATE_SUBMITTED" } });
    expect(JSON.stringify(made)).not.toContain("QUFB"); // the sender's own sealed text is not echoed back

    // The target receives the sealed parts as the status message, from the caller.
    const first = await bob.event();
    expect(first.a2a).toBe("1.0");
    expect(first.task.status.state).toBe("TASK_STATE_SUBMITTED");
    expect(first.task.status.message).toMatchObject({ taskId: "tk", role: "ROLE_USER", parts: [sealed("QUFB"), sealed("QkJC")], metadata: { parley: { kind: "TASK", from: "alice" } } });

    const status = await w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_AGENT", "STATUS", { seq: 1 }, [sealed("U1RBVFVT")]));
    expect(status.result.task.status.state).toBe("TASK_STATE_WORKING");
    const s = await alice.event();
    expect(s.task.status).toMatchObject({ state: "TASK_STATE_WORKING", message: { role: "ROLE_AGENT", parts: [sealed("U1RBVFVT")], metadata: { parley: { kind: "STATUS", from: "bob", seq: 1 } } } });

    const q = await w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_AGENT", "INPUT_REQUIRED", { seq: 2 }, [sealed("UVVFU1Q=")]));
    expect(q.result.task.status.state).toBe("TASK_STATE_INPUT_REQUIRED");
    expect((await alice.event()).task.status.state).toBe("TASK_STATE_INPUT_REQUIRED");
    expect(await w.state("tk")).toBe("TASK_STATE_INPUT_REQUIRED");

    const reply = await w.rpc("alice", "SendMessage", w.msg("tk", "ROLE_USER", "REPLY", { seq: 1 }, [sealed("QU5T")]));
    expect(reply.result.task.status.state).toBe("TASK_STATE_WORKING");
    const r = await bob.event();
    expect(r.task.status).toMatchObject({ state: "TASK_STATE_WORKING", message: { role: "ROLE_USER", metadata: { parley: { kind: "REPLY", seq: 1 } } } });

    const done = await w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_AGENT", "RESULT", { seq: 3 }));
    expect(done.result.task.status.state).toBe("TASK_STATE_COMPLETED");
    expect((await alice.event()).task.status.state).toBe("TASK_STATE_COMPLETED");
    expect(await w.state("tk", "bob")).toBe("TASK_STATE_COMPLETED");
  });

  it("maps every target kind to its A2A state", async () => {
    for (const [kind, state] of [["INPUT_REQUIRED", "INPUT_REQUIRED"], ["ERROR", "FAILED"], ["REJECTED", "REJECTED"], ["RESULT", "COMPLETED"], ["STATUS", "WORKING"]] as const) {
      const w = world();
      await connect(w.T, "alice");
      await connect(w.T, "bob");
      await w.task("tk");
      const r = await w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_AGENT", kind, { seq: 1 }));
      expect(r.result.task.status.state, kind).toBe(STATE_NAME[state]);
    }
  });

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
    await connect(w.T, "bob");
    // Alice has no tunnel, but the task exists: create it through a connected alice, then drop her.
    const alice = await connect(w.T, "alice");
    await w.task("tk");
    alice.ws.close(1000, "bye");
    for (let i = 0; i < 100; i++) {
      if (!(await (env.DEVICE.get(env.DEVICE.idFromName(`${w.T}:alice`)) as any).status()).connected) break;
      await new Promise((r) => setTimeout(r, 10));
    }
    const r = await w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_AGENT", "STATUS", { seq: 1 }));
    expect(errCode(r)).toBe(-32010);
    const t = await w.rpc("bob", "GetTask", { id: "tk" });
    expect(t.result.task.status.state).toBe("TASK_STATE_FAILED");
    expect(t.result.task.metadata.parley.reason).toBe("disconnected");
  });

  it("a reply the target never received fails the task instead of leaving it waiting", async () => {
    const w = world();
    await connect(w.T, "alice");
    const bob = await connect(w.T, "bob");
    await w.task("tk");
    await w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_AGENT", "INPUT_REQUIRED", { seq: 1 }));
    bob.ws.close(1000, "bye");
    for (let i = 0; i < 100; i++) {
      if (!(await (env.DEVICE.get(env.DEVICE.idFromName(`${w.T}:bob`)) as any).status()).connected) break;
      await new Promise((r) => setTimeout(r, 10));
    }
    expect(errCode(await w.rpc("alice", "SendMessage", w.msg("tk", "ROLE_USER", "REPLY", { seq: 1 })))).toBe(-32010);
    expect(await w.state("tk")).toBe("TASK_STATE_FAILED");
  });

  it("treats prototype property names as unknown kinds", async () => {
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    await w.task("tk");
    for (const [dev, role] of [["bob", "ROLE_AGENT"], ["alice", "ROLE_USER"]] as const) {
      for (const k of ["constructor", "toString", "__proto__"]) {
        expect(errCode(await w.rpc(dev, "SendMessage", w.msg("tk", role, k, { seq: 1 }))), k).toBe(-32602);
      }
    }
  });

  it("refuses out-of-order, replayed, wrong-side and late messages", async () => {
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    await w.task("tk");
    const st = (seq: unknown, kind = "STATUS") => w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_AGENT", kind, { seq }));
    expect((await st(2)).result).toBeDefined();
    expect(errCode(await st(2))).toBe(-32011); // replay
    expect(errCode(await st(1))).toBe(-32011); // reorder
    expect(errCode(await st(-1))).toBe(-32602);
    expect(errCode(await st(1.5))).toBe(-32602);
    expect(errCode(await st(undefined))).toBe(-32602);
    expect(errCode(await w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_AGENT", "NOPE", { seq: 5 })))).toBe(-32602);
    expect(errCode(await w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_AGENT", "STATUS", { seq: 5, to: "alice" })))).toBe(-32602);
    expect(errCode(await w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_USER", "STATUS", { seq: 5 })))).toBe(-32602); // wrong role
    // Each side may send only its own kinds.
    expect(errCode(await w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_USER", "REPLY", { seq: 5 })))).toBe(-32602);
    expect(errCode(await w.rpc("alice", "SendMessage", w.msg("tk", "ROLE_AGENT", "RESULT", { seq: 5 })))).toBe(-32602);
    // A reply needs a question.
    expect(errCode(await w.rpc("alice", "SendMessage", w.msg("tk", "ROLE_USER", "REPLY", { seq: 1 })))).toBe(-32015);
    expect(errCode(await w.rpc("alice", "SendMessage", w.msg("tk", "ROLE_USER", "TASK", { to: "bob" })))).toBe(-32012);
    // After a terminal state nothing is accepted.
    expect((await st(3, "RESULT")).result).toBeDefined();
    expect(errCode(await st(4))).toBe(-32015);
  });

  it("a third device, another tenant and a missing task all look like no task", async () => {
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    await w.task("tk");
    const hint = w.msg("tk", "ROLE_AGENT", "STATUS", { seq: 1 });
    expect(errCode(await w.rpc("mallory", "SendMessage", hint))).toBe(-32001);
    expect(errCode(await w.rpc("mallory", "GetTask", { id: "tk" }))).toBe(-32001);
    expect(errCode(await w.rpc("mallory", "CancelTask", cancelParams("tk", 1)))).toBe(-32001);
    expect(errCode(await w.rpc("bob", "GetTask", { id: "nope" }))).toBe(-32001);
    expect(errCode(await w.rpc("bob", "SendMessage", w.msg("nope", "ROLE_AGENT", "STATUS", { seq: 1 })))).toBe(-32001);
    expect(errCode(await w.rpc("bob", "CancelTask", cancelParams("nope", 1)))).toBe(-32001);
    const other = fresh();
    const r = await SELF.fetch("https://gw/a2a", { method: "POST", headers: other.bearer("alice"), body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "GetTask", params: { id: "tk" } }) });
    expect(errCode(await r.json())).toBe(-32001);
    expect(errCode(await w.rpc("alice", "GetTask", { id: "a/b" }))).toBe(-32602);
    expect(errCode(await w.rpc("alice", "GetTask", { id: "tk", extra: 1 }))).toBe(-32602);
    expect((await w.rpc("alice", "GetTask", { id: "tk", historyLength: 0 })).result).toBeDefined();
  });

  it("a message too big for one tunnel frame is refused and a new task is closed", async () => {
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    // Fits the request cap, but the framed event is over the frame limit.
    const over = () => [sealed("QUFB".repeat((MAX_FRAME_BYTES - 200) / 4))];
    const r = await w.rpc("alice", "SendMessage", w.msg("tk", "ROLE_USER", "TASK", { to: "bob" }, over()));
    expect(errCode(r)).toBe(-32014);
    expect(await w.state("tk")).toBe("TASK_STATE_CANCELED");
    // The target reporting a result too big for the caller's frame is refused too.
    await w.task("tk3");
    expect(errCode(await w.rpc("bob", "SendMessage", w.msg("tk3", "ROLE_AGENT", "RESULT", { seq: 1 }, over())))).toBe(-32014);
  });
});

it("the gateway stores no part bytes: task storage holds metadata only", async () => {
  const w = world();
  await connect(w.T, "alice");
  await connect(w.T, "bob");
  const canary = "Q0FOQVJZLUNPTlRFTlQ="; // sealed bytes the gateway must never keep
  await w.rpc("alice", "SendMessage", w.msg("tk", "ROLE_USER", "TASK", { to: "bob" }, [sealed(canary)]));
  await w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_AGENT", "RESULT", { seq: 1 }, [sealed(canary)]));
  const dump = JSON.stringify(
    await runInDurableObject(env.TASK.get(env.TASK.idFromName(`${w.T}:tk`)), async (_, ctx) => Object.fromEntries(await ctx.storage.list())),
  );
  expect(dump).toContain('"state":"COMPLETED"');
  expect(dump).not.toContain(canary);
});

const cancelParams = (id: string, seq: unknown, parts: unknown = [sealed("Q0FOQ0VM")], messageId = "c1") => ({ id, metadata: { parley: { seq, parts, messageId } } });

describe("cancel", () => {
  it("cancels with a sealed, sequenced message that the target receives", async () => {
    const w = world();
    await connect(w.T, "alice");
    const bob = await connect(w.T, "bob");
    await w.task("tk");
    await bob.event();
    const r = await w.rpc("alice", "CancelTask", cancelParams("tk", 1));
    expect(r.result.task.status.state).toBe("TASK_STATE_CANCELED");
    expect(r.result.task.metadata.parley.reason).toBe("canceled");
    const e = await bob.event();
    expect(e.task.status).toMatchObject({ state: "TASK_STATE_CANCELED", message: { role: "ROLE_USER", parts: [sealed("Q0FOQ0VM")], metadata: { parley: { kind: "CANCEL", from: "alice", seq: 1 } } } });
    // Late traffic from either side is refused.
    expect(errCode(await w.rpc("bob", "SendMessage", w.msg("tk", "ROLE_AGENT", "RESULT", { seq: 1 })))).toBe(-32015);
    expect(errCode(await w.rpc("alice", "CancelTask", cancelParams("tk", 2)))).toBe(-32002);
  });

  it("still cancels when the target is offline", async () => {
    const w = world();
    await connect(w.T, "alice");
    const bob = await connect(w.T, "bob");
    await w.task("tk");
    bob.ws.close(1000, "bye");
    expect((await w.rpc("alice", "CancelTask", cancelParams("tk", 1))).result.task.status.state).toBe("TASK_STATE_CANCELED");
  });

  it("only the caller cancels, with a proper message", async () => {
    const w = world();
    await connect(w.T, "alice");
    await connect(w.T, "bob");
    await w.task("tk");
    expect(errCode(await w.rpc("bob", "CancelTask", cancelParams("tk", 1)))).toBe(-32013);
    expect(errCode(await w.rpc("alice", "CancelTask", cancelParams("tk", 0)))).toBe(-32011);
    for (const p of [
      { id: "tk" }, // a bare A2A cancel cannot be authenticated by the target
      { id: "tk", metadata: {} },
      { id: "tk", metadata: { parley: { seq: 1, messageId: "c1" } } },
      { id: "tk", metadata: { parley: { seq: 1, parts: [{ text: "x" }], messageId: "c1" } } },
      { id: "tk", metadata: { parley: { seq: -1, parts: [sealed()], messageId: "c1" } } },
      { id: "tk", metadata: { parley: { seq: 1, parts: [sealed()] } } },
      { id: "tk", metadata: { parley: { seq: 1, parts: [sealed()], messageId: "c1", note: "x" } } },
      { id: "tk", metadata: { other: 1 } },
      { id: "tk", metadata: { parley: [] } },
      { id: "a/b", metadata: { parley: { seq: 1, parts: [sealed()], messageId: "c1" } } },
      { ...cancelParams("tk", 1), extra: 1 },
    ]) expect(errCode(await w.rpc("alice", "CancelTask", p)), JSON.stringify(p)).toBe(-32602);
    expect(await w.state("tk")).toBe("TASK_STATE_SUBMITTED");
  });
});
