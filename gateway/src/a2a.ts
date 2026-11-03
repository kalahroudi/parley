// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import type { Env } from "./index";
import { byteLength, MAX_FRAME_BYTES } from "./protocol";
import type { Task, TaskEvent, TaskRecord, TaskState } from "./task";

// A2A v1.0, JSON-RPC binding, on one endpoint (POST /a2a). The REST binding puts
// task ids in URLs, which the logging rules forbid, so it is not offered. Every
// message part is an opaque sealed envelope: the gateway checks the shape and
// relays it, and refuses any part, field or metadata key that could carry
// readable content (text, data, url, filename, free-form metadata). The state
// the gateway reports is a hint; the signed message inside the part is the
// authoritative one (checked by the daemons).

export const SEALED_MEDIA_TYPE = "application/vnd.parley.sealed";
export const MAX_PARTS = 8;
// A request may be a little larger than one tunnel frame (the JSON-RPC wrapper); the framed event is checked against the frame limit when it is delivered.
export const MAX_REQUEST_BYTES = MAX_FRAME_BYTES + 1024;

export const STATE_NAME: Readonly<Record<TaskState, string>> = {
  SUBMITTED: "TASK_STATE_SUBMITTED",
  WORKING: "TASK_STATE_WORKING",
  INPUT_REQUIRED: "TASK_STATE_INPUT_REQUIRED",
  COMPLETED: "TASK_STATE_COMPLETED",
  FAILED: "TASK_STATE_FAILED",
  CANCELED: "TASK_STATE_CANCELED",
  REJECTED: "TASK_STATE_REJECTED",
};

// JSON-RPC and A2A error codes (-32001 to -32005), then ours. Messages are fixed
// text: an error never repeats anything the caller sent.
const ERR = {
  parse: [-32700, "parse error"],
  request: [-32600, "invalid request"],
  method: [-32601, "method not found"],
  params: [-32602, "invalid params"],
  notFound: [-32001, "task not found"],
  notCancelable: [-32002, "task cannot be canceled"],
  pushUnsupported: [-32003, "push notifications are not supported"],
  unsupported: [-32004, "operation not supported"],
  offline: [-32010, "recipient offline"],
  badSeq: [-32011, "bad sequence number"],
  exists: [-32012, "task already exists"],
  forbidden: [-32013, "not permitted"],
  tooLarge: [-32014, "message too large"],
  transition: [-32015, "task state does not allow this"],
} as const;
type Err = (typeof ERR)[keyof typeof ERR];

// Which sender may send which kind, and the Task DO event it maps to. TASK
// creates the task. REPLY answers an INPUT_REQUIRED question on the same task.
const CALLER_KINDS: Readonly<Record<string, TaskEvent | "TASK">> = { TASK: "TASK", REPLY: "REPLY" };
const TARGET_KINDS: Readonly<Record<string, TaskEvent>> = {
  STATUS: "WORKING",
  INPUT_REQUIRED: "INPUT_REQUIRED",
  RESULT: "COMPLETED",
  ERROR: "FAILED",
  REJECTED: "REJECTED",
};

const ID = /^[A-Za-z0-9_-]{1,64}$/;
const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const onlyKeys = (o: Record<string, unknown>, ...keys: string[]) => Object.keys(o).every((k) => keys.includes(k));
const isId = (v: unknown): v is string => typeof v === "string" && ID.test(v);
const isSeq = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

interface Part {
  raw: string;
  mediaType: string;
}

function parseParts(v: unknown): Part[] | null {
  if (!Array.isArray(v) || v.length < 1 || v.length > MAX_PARTS) return null;
  const parts: Part[] = [];
  for (const p of v) {
    if (!isObj(p) || !onlyKeys(p, "raw", "mediaType")) return null;
    if (p.mediaType !== SEALED_MEDIA_TYPE || typeof p.raw !== "string" || p.raw.length === 0 || p.raw.length % 4 !== 0 || !B64.test(p.raw)) return null;
    parts.push({ raw: p.raw, mediaType: SEALED_MEDIA_TYPE });
  }
  return parts;
}

type Json = Record<string, unknown>;
const ok = (id: unknown, result: Json) => Response.json({ jsonrpc: "2.0", id, result }, { headers: { "cache-control": "no-store" } });
const fail = (id: unknown, [code, message]: Err) =>
  Response.json({ jsonrpc: "2.0", id, error: { code, message } }, { headers: { "cache-control": "no-store" } });

// The public card for the gateway's transport. Per-bot cards come with the
// directory (T303).
export function agentCard(origin: string): Json {
  return {
    name: "Parley gateway",
    description: "A2A v1.0 transport and lifecycle with end-to-end encrypted message parts. Content needs a Parley daemon or SDK.",
    version: "1.0.0",
    supportedInterfaces: [{ url: `${origin}/a2a`, protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
    capabilities: { streaming: false, pushNotifications: false },
    defaultInputModes: [SEALED_MEDIA_TYPE],
    defaultOutputModes: [SEALED_MEDIA_TYPE],
    skills: [],
  };
}

export interface Identity {
  tenant: string;
  device: string;
}

const taskStub = (env: Env, tenant: string, id: string) => env.TASK.get(env.TASK.idFromName(`${tenant}:${id}`)) as DurableObjectStub<Task>;
const deviceStub = (env: Env, tenant: string, device: string) => env.DEVICE.get(env.DEVICE.idFromName(`${tenant}:${device}`));

// Task view for responses: metadata only.
function view(rec: TaskRecord): Json {
  return {
    id: rec.id,
    contextId: rec.id, // the gateway keeps no context id; the signed one is inside the sealed part
    status: { state: STATE_NAME[rec.state], timestamp: new Date(rec.updated).toISOString() },
    metadata: { parley: { expires_at: rec.expires_at, ...(rec.reason ? { reason: rec.reason } : {}) } },
  };
}

// What the peer's daemon receives over its tunnel: the task with the sealed
// message as the status message, as A2A carries status text.
function eventBody(rec: TaskRecord, from: string, kind: string, seq: number | undefined, role: string, messageId: string, contextId: string | undefined, parts: Part[]): string {
  const t = view(rec);
  return JSON.stringify({
    a2a: "1.0",
    task: {
      ...t,
      status: {
        ...(t.status as Json),
        message: {
          messageId,
          taskId: rec.id,
          contextId: contextId ?? rec.id,
          role,
          parts,
          metadata: { parley: { kind, from, ...(seq === undefined ? {} : { seq }) } },
        },
      },
    },
  });
}

const APPLY_ERR: Readonly<Record<string, Err>> = {
  not_found: ERR.notFound,
  forbidden: ERR.forbidden,
  bad_seq: ERR.badSeq,
  bad_transition: ERR.transition,
  terminal: ERR.transition,
};

export async function handleA2A(req: Request, env: Env, who: Identity): Promise<Response> {
  if (req.method !== "POST") return new Response("method not allowed", { status: 405, headers: { allow: "POST" } });
  if (Number(req.headers.get("content-length") ?? 0) > MAX_REQUEST_BYTES) return new Response("too large", { status: 413 });
  const text = await req.text();
  if (text.length > MAX_REQUEST_BYTES || byteLength(text) > MAX_REQUEST_BYTES) return new Response("too large", { status: 413 });
  let rpc: unknown;
  try {
    rpc = JSON.parse(text);
  } catch {
    return fail(null, ERR.parse);
  }
  if (!isObj(rpc) || rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string") return fail(null, ERR.request);
  const id = rpc.id;
  if (!(typeof id === "string" || (typeof id === "number" && Number.isFinite(id)) || id === null)) return fail(null, ERR.request);
  const params = rpc.params;
  if (!isObj(params)) return fail(id, ERR.params);

  switch (rpc.method) {
    case "SendMessage":
      return send(id, params, env, who);
    case "GetTask":
      return get(id, params, env, who);
    case "CancelTask":
      return cancel(id, params, env, who);
    case "ListTasks": // needs a per-device task index, which the gateway does not keep
    case "SendStreamingMessage": // the tunnel is the event channel
    case "SubscribeToTask":
    case "GetExtendedAgentCard":
      return fail(id, ERR.unsupported);
    case "CreateTaskPushNotificationConfig":
    case "GetTaskPushNotificationConfig":
    case "ListTaskPushNotificationConfigs":
    case "DeleteTaskPushNotificationConfig":
      return fail(id, ERR.pushUnsupported);
    default:
      return fail(id, ERR.method);
  }
}

// parley metadata: only the routing hints below. Anything else is refused, so
// metadata cannot smuggle readable content past the gateway.
function parleyMeta(v: unknown, ...allowed: string[]): Record<string, unknown> | null {
  if (v === undefined) return {};
  if (!isObj(v) || !onlyKeys(v, "parley")) return null;
  const p = v.parley;
  return isObj(p) && onlyKeys(p, ...allowed) ? p : null;
}

async function send(rid: unknown, params: Json, env: Env, who: Identity): Promise<Response> {
  const m = params.message;
  if (!isObj(m) || !onlyKeys(params, "message") || !onlyKeys(m, "messageId", "contextId", "taskId", "role", "parts", "metadata")) return fail(rid, ERR.params);
  const meta = parleyMeta(m.metadata, "kind", "to", "seq");
  const parts = parseParts(m.parts);
  if (!meta || !parts || !isId(m.messageId) || !isId(m.taskId) || (m.contextId !== undefined && !isId(m.contextId))) return fail(rid, ERR.params);
  const kind = meta.kind;
  if (typeof kind !== "string") return fail(rid, ERR.params);
  const contextId = m.contextId as string | undefined;
  const stub = taskStub(env, who.tenant, m.taskId);

  if (kind === "TASK") {
    // A new task: the caller names the target and the task id.
    if (m.role !== "ROLE_USER" || !isId(meta.to) || meta.seq !== undefined) return fail(rid, ERR.params);
    const rec = await stub.create({ tenant: who.tenant, id: m.taskId, caller: who.device, target: meta.to });
    if (rec === "exists") return fail(rid, ERR.exists);
    if (rec === "bad_request") return fail(rid, ERR.params);
    const d = await deviceStub(env, who.tenant, meta.to).deliver(eventBody(rec, who.device, kind, undefined, "ROLE_USER", m.messageId, contextId, parts));
    if (d.status !== "delivered") {
      // The target never saw it: close the task so it does not sit until expiry. The
      // caller sends a new task (new id, fresh prekey) when the target is back.
      await stub.apply(who.tenant, who.device, "CANCEL", 1);
      return fail(rid, d.status === "offline" ? ERR.offline : ERR.tooLarge);
    }
    return ok(rid, { task: view(rec) });
  }

  const found = await stub.get(who.tenant);
  if (!found || (found.caller !== who.device && found.target !== who.device)) return fail(rid, ERR.notFound);
  const fromCaller = found.caller === who.device;
  const kinds = fromCaller ? CALLER_KINDS : TARGET_KINDS;
  const event = Object.hasOwn(kinds, kind) ? kinds[kind] : undefined; // not the prototype's "constructor" and the like
  if (!event || event === "TASK" || m.role !== (fromCaller ? "ROLE_USER" : "ROLE_AGENT") || meta.to !== undefined || !isSeq(meta.seq)) return fail(rid, ERR.params);

  const rec = await stub.apply(who.tenant, who.device, event, meta.seq);
  if (typeof rec === "string") return fail(rid, APPLY_ERR[rec]!);
  const peer = fromCaller ? rec.target : rec.caller;
  const d = await deviceStub(env, who.tenant, peer).deliver(eventBody(rec, who.device, kind, meta.seq, m.role as string, m.messageId, contextId, parts));
  if (d.status === "delivered") return ok(rid, { task: view(rec) });
  // Results and status are relayed only while the caller is connected (Strict).
  // The retention modes (T304) add the Queued behavior.
  // A reply the target never saw leaves the task waiting on an answer nobody can act on: close it.
  await stub.callerDisconnected(who.tenant, fromCaller ? who.device : rec.caller);
  return fail(rid, d.status === "offline" ? ERR.offline : ERR.tooLarge);
}

async function get(rid: unknown, params: Json, env: Env, who: Identity): Promise<Response> {
  if (!isId(params.id) || !onlyKeys(params, "id", "historyLength")) return fail(rid, ERR.params);
  const rec = await taskStub(env, who.tenant, params.id).get(who.tenant);
  if (!rec || (rec.caller !== who.device && rec.target !== who.device)) return fail(rid, ERR.notFound);
  return ok(rid, { task: view(rec) });
}

// A cancel must reach the target as a signed message, so it carries a sealed part
// and a sequence number in metadata.parley. A bare A2A CancelTask is refused: the
// target would have no way to tell it from a gateway forgery.
async function cancel(rid: unknown, params: Json, env: Env, who: Identity): Promise<Response> {
  const meta = isObj(params.metadata) && onlyKeys(params.metadata, "parley") && isObj(params.metadata.parley) ? params.metadata.parley : null;
  if (!isId(params.id) || !onlyKeys(params, "id", "metadata") || !meta || !onlyKeys(meta, "seq", "parts", "messageId") || !isSeq(meta.seq) || !isId(meta.messageId)) {
    return fail(rid, ERR.params);
  }
  const parts = parseParts(meta.parts);
  if (!parts) return fail(rid, ERR.params);
  const stub = taskStub(env, who.tenant, params.id);
  const rec = await stub.apply(who.tenant, who.device, "CANCEL", meta.seq);
  if (typeof rec === "string") {
    // A task that is not the caller's looks like one that does not exist.
    const found = rec === "forbidden" ? await stub.get(who.tenant) : null;
    if (rec === "forbidden" && found?.target !== who.device) return fail(rid, ERR.notFound);
    return fail(rid, rec === "terminal" || rec === "bad_transition" ? ERR.notCancelable : APPLY_ERR[rec]!);
  }
  // Delivery is best effort: the task is canceled either way, and an offline
  // target has lost its keys or will fail the task at expiry.
  await deviceStub(env, who.tenant, rec.target).deliver(eventBody(rec, who.device, "CANCEL", meta.seq, "ROLE_USER", meta.messageId as string, undefined, parts));
  return ok(rid, { task: view(rec) });
}
