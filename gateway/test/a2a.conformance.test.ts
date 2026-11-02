// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Shape conformance with A2A v1.0, checked with the official SDK (@a2a-js/sdk, the
// protobuf-generated v1.0 types) and not with our own idea of the spec: every
// object the gateway serves or relays must survive the SDK's fromJSON/toJSON round
// trip unchanged (so it has no field the SDK does not know and none in the wrong
// shape), every request it accepts must be one the SDK's client produces, and the
// SDK's client must work against it. T306 runs the full lifecycle on top of this;
// the deviations from the spec are listed in the header of src/a2a.ts.

import { describe, expect, it } from "vitest";
import { AgentCard, Message, Role, SendMessageRequest, SendMessageResponse, Task, TaskState, taskStateFromJSON } from "@a2a-js/sdk";
import { ClientFactory, ClientFactoryOptions, JsonRpcTransportFactory } from "@a2a-js/sdk/client";
import { TaskNotFoundError, UnsupportedOperationError, PushNotificationNotSupportedError, ContentTypeNotSupportedError } from "@a2a-js/sdk/errors";
import { agentCard, SEALED_MEDIA_TYPE, STATE_NAME } from "../src/a2a";
import type { SignedKind } from "../src/parts";
import { b64, encodeWire, header, taskBytes, taskHex, gw } from "./wire";

// What toJSON leaves out: defaults (empty strings and lists, false, 0).
function strip(v: any): any {
  if (Array.isArray(v)) return v.length ? v.map(strip) : undefined;
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      const s = strip(x);
      if (s !== undefined) out[k] = s;
    }
    return Object.keys(out).length ? out : undefined;
  }
  return v === "" || v === false || v === 0 || v === null ? undefined : v;
}
interface Codec {
  fromJSON(o: any): any;
  toJSON(m: any): unknown;
}
// The object must be exactly what the SDK would write for it.
const conforms = (codec: Codec, what: string, obj: unknown) => expect(strip(codec.toJSON(codec.fromJSON(obj))), what).toEqual(strip(JSON.parse(JSON.stringify(obj))));

let n = 0;
const tenant = () => `c${++n}`;
const sealedPart = (T: string, kind: SignedKind, task: string, from: string, to: string, seq = kind === "TASK" ? 0 : 1) => ({
  raw: b64(encodeWire({ header: header(kind, { tenant: T, sender: from, target: to, task: taskBytes(task), seq }) })),
  mediaType: SEALED_MEDIA_TYPE,
});

async function connect(T: string, device: string) {
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
  await next();
  return { event: async () => JSON.parse((await next()).body) };
}

// The SDK's own client, speaking JSON-RPC to the gateway as `device`.
async function sdkClient(T: string, device: string, seen: any[] = []) {
  const fetchImpl = (async (url: any, init: any) => {
    seen.push(JSON.parse(init.body));
    return gw(url, { ...init, headers: { ...(init?.headers ?? {}), Authorization: `Bearer dev:${T}:${device}` } });
  }) as typeof fetch;
  const f = new ClientFactory(ClientFactoryOptions.createFrom(ClientFactoryOptions.default, { transports: [new JsonRpcTransportFactory({ fetchImpl })] }));
  const card = await (await gw("https://gw/.well-known/agent-card.json")).json();
  return f.createFromAgentCard(AgentCard.fromJSON(card));
}

describe("A2A v1.0 shapes, by the official SDK", () => {
  it("the agent card is a v1.0 card, served at the well-known path", async () => {
    const card: any = await (await gw("https://gw/.well-known/agent-card.json")).json();
    expect(card).toEqual(agentCard("https://gw"));
    conforms(AgentCard, "agent card", card);
    expect(card.supportedInterfaces[0]).toMatchObject({ protocolBinding: "JSONRPC", protocolVersion: "1.0" });
    for (const k of ["name", "description", "version", "supportedInterfaces", "capabilities", "defaultInputModes", "defaultOutputModes", "skills"]) expect(card, k).toHaveProperty(k);
  });

  it("every task state name is a v1.0 TaskState", () => {
    for (const [state, name] of Object.entries(STATE_NAME)) {
      expect(taskStateFromJSON(name), state).not.toBe(TaskState.UNRECOGNIZED);
      expect(taskStateFromJSON(name), state).not.toBe(TaskState.TASK_STATE_UNSPECIFIED);
    }
    expect(Object.keys(STATE_NAME)).toHaveLength(7);
  });

  it("the requests it accepts are SDK requests, and SDK clients' requests are accepted", async () => {
    const T = tenant();
    await connect(T, "bob");
    const seen: any[] = [];
    const client = await sdkClient(T, "alice", seen);
    const part = sealedPart(T, "TASK", "sdk1", "alice", "bob");
    const message = { messageId: "m1", role: Role.ROLE_USER, parts: [{ content: { $case: "raw" as const, value: Buffer.from(part.raw, "base64") }, mediaType: SEALED_MEDIA_TYPE, filename: "", metadata: undefined }], contextId: "", taskId: "", metadata: undefined, extensions: [], referenceTaskIds: [] };
    const r = await client.sendMessage({ message, configuration: undefined, metadata: undefined, tenant: "" } as any);
    const sent = seen.at(-1);
    expect(sent.method).toBe("SendMessage");
    conforms(SendMessageRequest, "the SDK's request", sent.params);
    expect(sent.params.message.parts[0]).toEqual(part); // base64 raw + mediaType, nothing else
    expect((r as any).id ?? (r as any).payload?.value?.id ?? (r as any).task?.id ?? JSON.stringify(r)).toContain(taskHex("sdk1"));
  });

  it("every task the gateway serves or relays is an SDK Task", async () => {
    const T = tenant();
    const alice = await connect(T, "alice");
    const bob = await connect(T, "bob");
    const rpc = async (device: string, method: string, params: unknown) =>
      (await (await gw("https://gw/a2a", { method: "POST", headers: { Authorization: `Bearer dev:${T}:${device}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) })).json()) as any;
    const send = (device: string, kind: SignedKind, task: string, from: string, to: string, seq?: number, role = device === "alice" ? "ROLE_USER" : "ROLE_AGENT") =>
      rpc(device, "SendMessage", { message: { messageId: `m${++n}`, role, parts: [sealedPart(T, kind, task, from, to, seq)] } });
    const check = (what: string, task: any) => {
      conforms(Task, what, task);
      expect(task.status.timestamp, what).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
      expect(task.contextId, what).toBeTruthy();
    };
    const step = async (what: string, device: string, kind: SignedKind, from: string, to: string, seq?: number, receiver = device === "alice" ? bob : alice) => {
      const r = await send(device, kind, "life", from, to, seq);
      check(`${what} response`, r.result.task);
      conforms(SendMessageResponse, `${what} SendMessageResponse`, r.result);
      const ev = await receiver.event();
      check(`${what} relayed`, ev.task);
      conforms(Message, `${what} relayed message`, ev.task.status.message);
      expect(ev.task.status.message.role).toBe(device === "alice" ? "ROLE_USER" : "ROLE_AGENT");
      expect(ev.task.status.message.parts).toHaveLength(1);
      expect(Object.keys(ev.task.status.message.parts[0]).sort()).toEqual(["mediaType", "raw"]);
      return r;
    };
    await step("TASK", "alice", "TASK", "alice", "bob");
    await step("STATUS", "bob", "STATUS", "bob", "alice", 1);
    await step("INPUT_REQUIRED", "bob", "INPUT_REQUIRED", "bob", "alice", 2);
    await step("REPLY", "alice", "REPLY", "alice", "bob", 1);
    await step("RESULT", "bob", "RESULT", "bob", "alice", 3);
    check("GetTask", (await rpc("alice", "GetTask", { id: taskHex("life") })).result);
    for (const [what, kind, hint] of [["ERROR", "ERROR", undefined], ["REJECTED", "ERROR", "REJECTED"]] as const) {
      const id = what.toLowerCase();
      await rpc("alice", "SendMessage", { message: { messageId: `m${++n}`, role: "ROLE_USER", parts: [sealedPart(T, "TASK", id, "alice", "bob")] } });
      await bob.event();
      const msg: any = { messageId: `m${++n}`, role: "ROLE_AGENT", parts: [sealedPart(T, kind, id, "bob", "alice", 1)] };
      if (hint) msg.metadata = { parley: { kind: hint } };
      const r = await rpc("bob", "SendMessage", { message: msg });
      check(what, r.result.task);
      check(`${what} relayed`, (await alice.event()).task);
    }
    await rpc("alice", "SendMessage", { message: { messageId: "mc", role: "ROLE_USER", parts: [sealedPart(T, "TASK", "cx", "alice", "bob")] } });
    await bob.event();
    const c = await rpc("alice", "CancelTask", { id: taskHex("cx"), metadata: { parley: { messageId: "c1", parts: [sealedPart(T, "CANCEL", "cx", "alice", "bob")] } } });
    check("CancelTask", c.result);
    const ev = await bob.event();
    check("CANCEL relayed", ev.task);
    expect(ev.task.status.state).toBe("TASK_STATE_CANCELED");
  });

  it("the SDK client works against it: getTask, cancelTask, and A2A errors by code", async () => {
    const T = tenant();
    await connect(T, "bob");
    const alice = await sdkClient(T, "alice");
    const part = sealedPart(T, "TASK", "sdk2", "alice", "bob");
    const res: any = await alice.sendMessage({ message: { messageId: "m2", role: Role.ROLE_USER, parts: [{ content: { $case: "raw", value: Buffer.from(part.raw, "base64") }, mediaType: SEALED_MEDIA_TYPE, filename: "", metadata: undefined }], contextId: "", taskId: "", metadata: undefined, extensions: [], referenceTaskIds: [] } } as any);
    const task = await alice.getTask({ id: taskHex("sdk2"), historyLength: undefined, tenant: "" } as any);
    expect(task.id).toBe(taskHex("sdk2"));
    expect(task.status?.state).toBe(TaskState.TASK_STATE_SUBMITTED);
    expect(res).toBeDefined();
    await expect(alice.getTask({ id: taskHex("missing"), historyLength: undefined, tenant: "" } as any)).rejects.toBeInstanceOf(TaskNotFoundError);
    // A bare cancel (no signed envelope) is a deviation: the SDK sees invalid params.
    await expect(alice.cancelTask({ id: taskHex("sdk2"), metadata: undefined, tenant: "" } as any)).rejects.toThrow();
    // Everything the gateway declines maps to the A2A error the SDK expects for that code.
    await expect(alice.listTasks({} as any)).rejects.toBeInstanceOf(UnsupportedOperationError);
    // The card says no push notifications, and the SDK's client honors that without asking.
    expect(() => alice.getTaskPushNotificationConfig({ taskId: "x", id: "y", tenant: "" } as any)).toThrow(PushNotificationNotSupportedError);
    const text = { ...part };
    await expect(alice.sendMessage({ message: { messageId: "m3", role: Role.ROLE_USER, parts: [{ content: { $case: "raw", value: Buffer.from(text.raw, "base64") }, mediaType: SEALED_MEDIA_TYPE, filename: "", metadata: undefined }], contextId: "", taskId: "", metadata: undefined, extensions: [], referenceTaskIds: [] }, configuration: { acceptedOutputModes: ["text/plain"], taskPushNotificationConfig: undefined, historyLength: undefined, returnImmediately: false } } as any)).rejects.toBeInstanceOf(ContentTypeNotSupportedError);
  });
});
