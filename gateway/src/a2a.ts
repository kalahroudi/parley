// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import type { Env } from "./index";
import { MAX_FRAME_BYTES } from "./protocol";
import { parseSealedPart, SEALED_MEDIA_TYPE, type Shape } from "./parts";
import type { Scope } from "./ratelimit";
import type { Task, TaskEvent, TaskRecord, TaskState } from "./task";
import type { Tenant } from "./tenant";

export { SEALED_MEDIA_TYPE };

// A2A v1.0, JSON-RPC binding, on one endpoint (POST /a2a). The REST binding puts
// task ids in URLs, which the logging rules forbid, so it is not offered. Every
// message part is an opaque sealed envelope: the gateway checks its shape
// (src/parts.ts) and relays it, and refuses any part, field or metadata key that
// could carry readable content (text, data, url, filename, free-form metadata).
// The state the gateway reports is a hint; the signed message inside the part is
// the authoritative one (checked by the daemons). The request's routing hints
// (task id, kind, sequence, recipient) are read from the sealed envelope's own
// plaintext header, and a request that disagrees with it is refused, so the
// gateway never relays a hint that contradicts the message the sender signed.
// The Task Durable Object (src/task.ts) is the only place a task changes state:
// every move here is a request to it, and it refuses what the machine forbids.
//
// Deviations from A2A v1.0, each deliberate:
//  - Parts carry only `raw` (a sealed envelope) and `mediaType`; `text`, `data`,
//    `url`, `filename` and part `metadata` are refused (they would be readable).
//    One part per message: a message is one envelope. Files travel as encrypted
//    objects named inside the sealed content.
//  - `taskId` is the lowercase hex of the 16-byte task id in the signed header,
//    so a client may omit it on a new task (as A2A clients do) and the gateway
//    uses the signed one. `contextId` is the signed header's; responses use the
//    task id as `contextId` because the gateway stores no context.
//  - SendMessage always returns at once with the task (as if returnImmediately
//    were set); progress comes over the tunnel or GetTask. No streaming, no
//    subscribe, no ListTasks (the gateway keeps no per-device task index), no
//    push notifications (capabilities say so).
//  - CancelTask must carry the signed CANCEL envelope in metadata.parley.parts,
//    because a bare cancel is indistinguishable from a gateway forgery.
//  - Extra JSON-RPC error codes -32010 to -32015, outside the A2A range -32001 to
//    -32009, for offline recipient, bad sequence, duplicate task, not permitted,
//    too large and illegal state move, and -32016 for a rate limit (with HTTP 429,
//    Retry-After and error.data.retry_after_ms; limits are in src/ratelimit.ts).
//  - `status.message` on tasks relayed to a daemon carries the sealed part and
//    metadata.parley {kind, from, seq}; `from` is the gateway's say-so and a
//    daemon must take the sender from the signed header, never from it.

export const MAX_PARTS = 1;
// A request may be a little larger than one tunnel frame (the JSON-RPC wrapper); the framed event is checked against the frame limit when it is delivered.
export const MAX_REQUEST_BYTES = MAX_FRAME_BYTES + 1024;
const MAX_RPC_ID = 128;

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
  contentType: [-32005, "content type not supported"],
  offline: [-32010, "recipient offline"],
  badSeq: [-32011, "bad sequence number"],
  exists: [-32012, "task already exists"],
  forbidden: [-32013, "not permitted"],
  tooLarge: [-32014, "message too large"],
  transition: [-32015, "task state does not allow this"],
  rateLimited: [-32016, "rate limited"],
} as const;
type Err = (typeof ERR)[keyof typeof ERR];

const ID = /^[A-Za-z0-9_-]{1,64}$/;
// A task id as the gateway names it: the lowercase hex of the 16 random bytes in the signed header. Nothing
// else is looked up, so an id cannot carry text into a Durable Object name.
const TASK_ID = /^[0-9a-f]{32}$/;
const isTaskId = (v: unknown): v is string => typeof v === "string" && TASK_ID.test(v);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const onlyKeys = (o: Record<string, unknown>, ...keys: string[]) => Object.keys(o).every((k) => keys.includes(k));
const isId = (v: unknown): v is string => typeof v === "string" && ID.test(v);
const isEmpty = (v: unknown) => v === undefined || (Array.isArray(v) && v.length === 0) || (isObj(v) && Object.keys(v).length === 0);

interface Part {
  raw: string;
  mediaType: string;
}

// Exactly one sealed part: a message is one envelope.
function parseParts(v: unknown): { parts: Part[]; shape: Shape } | null {
  if (!Array.isArray(v) || v.length !== MAX_PARTS) return null;
  const one = parseSealedPart(v[0]);
  return one && { parts: [{ raw: one.raw, mediaType: SEALED_MEDIA_TYPE }], shape: one.shape };
}

type Json = Record<string, unknown>;
const ok = (id: unknown, result: Json) => Response.json({ jsonrpc: "2.0", id, result }, { headers: { "cache-control": "no-store" } });
const fail = (id: unknown, [code, message]: Err) =>
  Response.json({ jsonrpc: "2.0", id, error: { code, message } }, { headers: { "cache-control": "no-store" } });

// Counts one request against the caller's allowance (Tenant DO). Null means go
// on; otherwise the response to return. Called after the request is known to be
// well formed and before anything is written or relayed.
async function limited(rid: unknown, env: Env, who: Identity, scope: Scope): Promise<Response | null> {
  const stub = env.TENANT.get(env.TENANT.idFromName(who.tenant)) as DurableObjectStub<Tenant>;
  const r = await stub.rateLimit(scope, who.device);
  if (r.ok) return null;
  return Response.json(
    { jsonrpc: "2.0", id: rid, error: { code: ERR.rateLimited[0], message: ERR.rateLimited[1], data: { retry_after_ms: r.retry_after_ms } } },
    { status: 429, headers: { "cache-control": "no-store", "retry-after": String(Math.ceil(r.retry_after_ms / 1000)) } },
  );
}

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
function eventBody(rec: TaskRecord, from: string, kind: string, seq: number | undefined, role: string, messageId: string, contextId: string, parts: Part[]): string {
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
          contextId,
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

// Reads the body without ever holding more than `max` bytes: a declared length
// over the cap is refused unread, and a stream is cut off at the cap, so a missing
// or false Content-Length cannot make us buffer more.
async function readBounded(req: Request, max: number): Promise<string | null> {
  if (Number(req.headers.get("content-length") ?? 0) > max) return null;
  if (!req.body) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.byteLength;
    if (n > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(n);
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(all);
}

export async function handleA2A(req: Request, env: Env, who: Identity): Promise<Response> {
  if (req.method !== "POST") return new Response("method not allowed", { status: 405, headers: { allow: "POST" } });
  let text: string | null;
  try {
    text = await readBounded(req, MAX_REQUEST_BYTES);
  } catch {
    return fail(null, ERR.parse); // not UTF-8
  }
  if (text === null) return new Response("too large", { status: 413 });
  let rpc: unknown;
  try {
    rpc = JSON.parse(text);
  } catch {
    return fail(null, ERR.parse);
  }
  if (!isObj(rpc) || rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string") return fail(null, ERR.request);
  const id = rpc.id;
  if (!((typeof id === "string" && id.length <= MAX_RPC_ID) || (typeof id === "number" && Number.isFinite(id)) || id === null)) return fail(null, ERR.request);
  const params = rpc.params;
  if (!isObj(params)) return fail(id, ERR.params);
  // A2A's multi-tenant path field: the tenant is the authenticated one, so this
  // may be empty or that tenant and nothing else.
  if (params.tenant !== undefined && params.tenant !== "" && params.tenant !== who.tenant) return fail(id, ERR.params);

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

// SendMessageConfiguration: the fields a standard client sends, checked and then
// ignored (the gateway always answers at once). A push config is refused; a client
// that accepts only other media types gets the content-type error.
function checkConfiguration(c: unknown): Err | null {
  if (c === undefined) return null;
  if (!isObj(c) || !onlyKeys(c, "acceptedOutputModes", "taskPushNotificationConfig", "historyLength", "returnImmediately")) return ERR.params;
  if (c.taskPushNotificationConfig !== undefined && c.taskPushNotificationConfig !== null) return ERR.pushUnsupported;
  if (c.historyLength !== undefined && !(Number.isSafeInteger(c.historyLength) && (c.historyLength as number) >= 0)) return ERR.params;
  if (c.returnImmediately !== undefined && typeof c.returnImmediately !== "boolean") return ERR.params;
  const modes = c.acceptedOutputModes;
  if (modes === undefined) return null;
  if (!Array.isArray(modes) || modes.length > 16 || !modes.every((m) => typeof m === "string" && m.length <= 128)) return ERR.params;
  return modes.length === 0 || modes.some((m) => m === SEALED_MEDIA_TYPE || m === "application/*" || m === "*/*") ? null : ERR.contentType;
}

async function send(rid: unknown, params: Json, env: Env, who: Identity): Promise<Response> {
  const m = params.message;
  if (!isObj(m) || !onlyKeys(params, "message", "configuration", "metadata", "tenant") || !isEmpty(params.metadata)) return fail(rid, ERR.params);
  if (!onlyKeys(m, "messageId", "contextId", "taskId", "role", "parts", "metadata", "extensions", "referenceTaskIds") || !isEmpty(m.extensions) || !isEmpty(m.referenceTaskIds)) return fail(rid, ERR.params);
  const cfg = checkConfiguration(params.configuration);
  if (cfg) return fail(rid, cfg);
  const meta = parleyMeta(m.metadata, "kind", "to", "seq");
  const sealed = parseParts(m.parts);
  if (!meta || !sealed || !isId(m.messageId)) return fail(rid, ERR.params);
  const { parts, shape } = sealed;
  // The sealed header is the truth about this message; the request may repeat it, never differ.
  if (shape.tenant !== who.tenant || shape.sender !== who.device) return fail(rid, ERR.params);
  if (m.taskId !== undefined && m.taskId !== shape.taskId) return fail(rid, ERR.params);
  if (m.contextId !== undefined && m.contextId !== shape.context) return fail(rid, ERR.params);
  if (meta.seq !== undefined && meta.seq !== shape.seq) return fail(rid, ERR.params);
  if (meta.to !== undefined && meta.to !== shape.target) return fail(rid, ERR.params);
  const hint = meta.kind;
  // REJECTED is an ERROR on the wire; any other hint must name the signed type.
  if (hint !== undefined && hint !== shape.kind && !(hint === "REJECTED" && shape.kind === "ERROR")) return fail(rid, ERR.params);
  const stub = taskStub(env, who.tenant, shape.taskId);
  const role = shape.kind === "TASK" || shape.kind === "REPLY" ? "ROLE_USER" : "ROLE_AGENT";
  if (m.role !== role) return fail(rid, ERR.params);
  const over = await limited(rid, env, who, shape.kind === "TASK" ? "task" : "message");
  if (over) return over;

  if (shape.kind === "TASK") {
    // A new task: the signed header names the target and the task id.
    if (!isId(shape.target)) return fail(rid, ERR.params);
    const rec = await stub.create({ tenant: who.tenant, id: shape.taskId, caller: who.device, target: shape.target });
    if (rec === "exists") return fail(rid, ERR.exists);
    if (rec === "bad_request") return fail(rid, ERR.params);
    const d = await deviceStub(env, who.tenant, shape.target).deliver(eventBody(rec, who.device, shape.kind, undefined, role, m.messageId, shape.context, parts));
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
  // Each side sends only its own kinds, and only to the other side.
  const event: TaskEvent | undefined = fromCaller
    ? shape.kind === "REPLY"
      ? "REPLY"
      : undefined
    : ({ STATUS: "WORKING", INPUT_REQUIRED: "INPUT_REQUIRED", RESULT: "COMPLETED", ERROR: hint === "REJECTED" ? "REJECTED" : "FAILED" } as Record<string, TaskEvent>)[shape.kind];
  if (!event || shape.target !== (fromCaller ? found.target : found.caller)) return fail(rid, ERR.params);

  const rec = await stub.apply(who.tenant, who.device, event, shape.seq);
  if (typeof rec === "string") return fail(rid, APPLY_ERR[rec]!);
  const peer = fromCaller ? rec.target : rec.caller;
  const d = await deviceStub(env, who.tenant, peer).deliver(eventBody(rec, who.device, (hint as string | undefined) ?? shape.kind, shape.seq, role, m.messageId, shape.context, parts));
  if (d.status === "delivered") return ok(rid, { task: view(rec) });
  // Results and status are relayed only while the caller is connected (Strict).
  // The retention modes (T304) add the Queued behavior. A reply the target never
  // saw leaves the task waiting on an answer nobody can act on: close it.
  await stub.callerDisconnected(who.tenant, fromCaller ? who.device : rec.caller);
  return fail(rid, d.status === "offline" ? ERR.offline : ERR.tooLarge);
}

async function get(rid: unknown, params: Json, env: Env, who: Identity): Promise<Response> {
  if (!isTaskId(params.id) || !onlyKeys(params, "id", "historyLength", "tenant")) return fail(rid, ERR.params);
  const over = await limited(rid, env, who, "message");
  if (over) return over;
  const rec = await taskStub(env, who.tenant, params.id).get(who.tenant);
  if (!rec || (rec.caller !== who.device && rec.target !== who.device)) return fail(rid, ERR.notFound);
  return ok(rid, view(rec)); // GetTask answers with the Task itself, not a SendMessageResponse
}

// A cancel must reach the target as a signed message, so it carries the sealed
// CANCEL envelope in metadata.parley.parts (and may repeat its messageId and
// sequence number). A bare A2A CancelTask is refused: the target would have no way
// to tell it from a gateway forgery.
async function cancel(rid: unknown, params: Json, env: Env, who: Identity): Promise<Response> {
  const meta = isObj(params.metadata) && onlyKeys(params.metadata, "parley") && isObj(params.metadata.parley) ? params.metadata.parley : null;
  if (!isTaskId(params.id) || !onlyKeys(params, "id", "metadata", "tenant") || !meta || !onlyKeys(meta, "seq", "parts", "messageId") || !isId(meta.messageId)) return fail(rid, ERR.params);
  const sealed = parseParts(meta.parts);
  if (!sealed) return fail(rid, ERR.params);
  const { parts, shape } = sealed;
  if (shape.kind !== "CANCEL" || shape.taskId !== params.id || shape.tenant !== who.tenant || shape.sender !== who.device) return fail(rid, ERR.params);
  if (meta.seq !== undefined && meta.seq !== shape.seq) return fail(rid, ERR.params);
  const over = await limited(rid, env, who, "message");
  if (over) return over;
  const stub = taskStub(env, who.tenant, params.id);
  // A task that is not the caller's looks like one that does not exist.
  const found = await stub.get(who.tenant);
  if (!found || (found.caller !== who.device && found.target !== who.device)) return fail(rid, ERR.notFound);
  if (found.caller !== who.device) return fail(rid, ERR.forbidden);
  if (shape.target !== found.target) return fail(rid, ERR.params);
  const rec = await stub.apply(who.tenant, who.device, "CANCEL", shape.seq);
  if (typeof rec === "string") return fail(rid, rec === "terminal" || rec === "bad_transition" ? ERR.notCancelable : APPLY_ERR[rec]!);
  // Delivery is best effort: the task is canceled either way, and an offline
  // target has lost its keys or will fail the task at expiry.
  await deviceStub(env, who.tenant, rec.target).deliver(eventBody(rec, who.device, "CANCEL", shape.seq, "ROLE_USER", meta.messageId, shape.context, parts));
  return ok(rid, view(rec)); // CancelTask answers with the Task itself
}
