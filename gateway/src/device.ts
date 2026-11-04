// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { DurableObject } from "cloudflare:workers";
import type { Env } from "./index";
import type { Task } from "./task";
import {
  CLOSE_PROTOCOL,
  CLOSE_REPLACED,
  CLOSE_TOO_LARGE,
  HEARTBEAT_MS,
  MAX_FRAME_BYTES,
  PROTOCOL_VERSION,
  byteLength,
  parseClientMessage,
  parseRelayFrame,
  type ServerMessage,
} from "./protocol";
import { limitDevice } from "./ratelimit";

// Set by the Worker on the request it forwards, after it has verified the device's token.
export const IDENTITY_TENANT = "x-parley-tenant";
export const IDENTITY_DEVICE = "x-parley-device";
const IDENTITY = /^[A-Za-z0-9_-]{1,64}$/;

// Per-connection state, kept in the socket attachment so it survives hibernation.
interface Attachment {
  ready: boolean;
  // Who is on the other end, from the Worker. Absent when the socket was not opened by the Worker
  // (the relay is then off for it).
  who?: { tenant: string; device: string };
}

// Session counters, kept in storage so a resume survives eviction. Metadata only.
interface Session {
  id: string;
  rx_seq: number; // highest daemon frame seq accepted
  tx_seq: number; // last event seq sent to the daemon
  acked_tx: number; // highest event seq the daemon acknowledged
}

// A task that holds sealed events for this device (Queued): ids and a deadline, no content.
export interface Held {
  tenant: string;
  device: string;
  task: string;
  until: number;
}
// A held event pushed on the tunnel, waiting for the daemon's acknowledgment of `seq`.
interface Inflight extends Held {
  id: number;
  seq: number;
}
export const MAX_HELD = 256;

export type DeliverResult =
  | { status: "delivered"; seq: number }
  | { status: "offline" }
  | { status: "too_large" };

// One Device DO per enrolled device (named `${tenant}:${device}`), holding the
// device's hibernating socket. It stores no frame bodies. Frames from a daemon
// are acknowledged by sequence number and de-duplicated, so a daemon that
// retransmits after a reconnect cannot cause a duplicate. Events pushed to the
// daemon are sent once and never replayed (the gateway does not queue task
// ciphertext); the sender retries if it needs delivery.
export class Device extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Heartbeats are answered without waking a hibernated object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  // Entry point from the Worker, which has already authenticated the caller.
  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }
    // A new connection supersedes the old one (the daemon reconnected). Closing makes
    // the old socket not open at once, so nothing is sent on it from here on.
    for (const old of this.ctx.getWebSockets()) {
      old.close(CLOSE_REPLACED, "replaced");
    }
    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1]);
    const tenant = request.headers.get(IDENTITY_TENANT);
    const device = request.headers.get(IDENTITY_DEVICE);
    const who = validId(tenant) && validId(device) ? { tenant, device } : undefined;
    pair[1].serializeAttachment({ ready: false, who } satisfies Attachment);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  // Pushes an opaque event to the connected daemon. An event whose encoded frame
  // would exceed MAX_FRAME_BYTES is refused here (the daemon could not read it).
  async deliver(body: string): Promise<DeliverResult> {
    // The envelope is under 64 bytes; seq is at most 16 digits.
    if (byteLength(JSON.stringify({ t: "event", seq: Number.MAX_SAFE_INTEGER, body })) > MAX_FRAME_BYTES) {
      return { status: "too_large" };
    }
    const ws = this.ctx.getWebSockets().find((s) => isOpen(s) && isReady(s));
    const session = await this.ctx.storage.get<Session>("session");
    // The daemon may drop at any await, so the socket is checked again each time.
    if (!ws || !session || !isOpen(ws)) return { status: "offline" };
    session.tx_seq += 1;
    await this.ctx.storage.put("session", session);
    // Closed during the write: the event was not sent (and its seq is skipped,
    // which the resume logic tolerates because events are never replayed).
    if (!send(ws, { t: "event", seq: session.tx_seq, body })) return { status: "offline" };
    return { status: "delivered", seq: session.tx_seq };
  }

  // Notes that a task holds sealed events for this device until `until`.
  async hold(h: Held): Promise<"ok" | "full"> {
    return this.ctx.blockConcurrencyWhile(async () => {
      const list = await this.liveHeld();
      const i = list.findIndex((x) => x.tenant === h.tenant && x.task === h.task);
      if (i >= 0) list[i] = { ...h, until: Math.max(h.until, list[i]!.until) };
      else if (list.length >= MAX_HELD) return "full";
      else list.push(h);
      await this.ctx.storage.put("held", list);
      return "ok";
    });
  }

  private async liveHeld(): Promise<Held[]> {
    const now = Date.now();
    return ((await this.ctx.storage.get<Held[]>("held")) ?? []).filter((h) => h.until > now);
  }

  private taskStub(h: Held) {
    return this.env.TASK.get(this.env.TASK.idFromName(`${h.tenant}:${h.task}`)) as DurableObjectStub<Task>;
  }

  // Deletes the held events the daemon has acknowledged (everything up to `upTo`).
  private async ackHeld(upTo: number): Promise<void> {
    const infl = (await this.ctx.storage.get<Inflight[]>("inflight")) ?? [];
    const done = infl.filter((i) => i.seq <= upTo);
    if (!done.length) return;
    for (const i of done) await this.taskStub(i).ack(i.tenant, i.device, i.id);
    await this.ctx.storage.put("inflight", infl.filter((i) => i.seq > upTo));
  }

  // Pushes every event held for this device, oldest first. Events stay held (and
  // are pushed again after a later reconnect) until the daemon acknowledges them.
  private async flush(ws: WebSocket): Promise<void> {
    await this.ctx.blockConcurrencyWhile(async () => {
      const session = (await this.ctx.storage.get<Session>("session"))!; // hello stored it before calling us
      await this.ackHeld(session.acked_tx);
      const [prevHeld, prevInfl] = await Promise.all([this.ctx.storage.get<Held[]>("held"), this.ctx.storage.get<Inflight[]>("inflight")]);
      const held: Held[] = [];
      const infl = (prevInfl ?? []).filter((i) => i.until > Date.now());
      const tx = session.tx_seq;
      for (const h of await this.liveHeld()) {
        const events = await this.taskStub(h).drain(h.tenant, h.device);
        if (typeof events === "string" || !events.length) continue; // the task holds nothing for us any more
        held.push(h);
        const first = session.tx_seq + 1;
        // `send` is false once the socket has closed. Those events were not sent, so they are not recorded
        // as in flight and stay held for the next connection (the sent ones are always the leading ones).
        const sent = events.filter((e) => {
          session.tx_seq += 1;
          return send(ws, { t: "event", seq: session.tx_seq, body: e.body });
        });
        infl.push(...sent.map((e, k) => ({ ...h, until: e.exp, id: e.id, seq: first + k })));
      }
      // Write only what changed: a connection with nothing held (always so in Strict) writes nothing here, which
      // also keeps the keys out of storage altogether.
      const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
      await Promise.all([
        ...(session.tx_seq === tx ? [] : [this.ctx.storage.put("session", session)]),
        ...(same(held, prevHeld ?? []) ? [] : [this.ctx.storage.put("held", held)]),
        ...(same(infl, prevInfl ?? []) ? [] : [this.ctx.storage.put("inflight", infl)]),
      ]);
    });
  }

  async webSocketMessage(ws: WebSocket, data: string | ArrayBuffer): Promise<void> {
    if (typeof data !== "string") return ws.close(CLOSE_PROTOCOL, "text frames only");
    if (byteLength(data) > MAX_FRAME_BYTES) return ws.close(CLOSE_TOO_LARGE, "frame too large");
    const msg = parseClientMessage(data);
    if (!msg) return reject(ws, "bad_message");

    if (msg.t === "hello") {
      if (isReady(ws)) return reject(ws, "duplicate_hello");
      const stored = await this.ctx.storage.get<Session>("session");
      const resumed = !!stored && !!msg.session && stored.id === msg.session;
      const session: Session = resumed
        ? stored
        : { id: crypto.randomUUID(), rx_seq: 0, tx_seq: 0, acked_tx: 0 };
      // Events the daemon says it received count as acknowledged.
      session.acked_tx = Math.max(session.acked_tx, Math.min(msg.last_rx, session.tx_seq));
      await this.ctx.storage.put("session", session);
      // Superseded or dropped during the write: the socket must not become ready, or it
      // would count as connected (and receive events) after its replacement is live.
      if (!isOpen(ws)) return;
      ws.serializeAttachment({ ...(ws.deserializeAttachment() as Attachment), ready: true } satisfies Attachment);
      send(ws, {
        t: "welcome",
        v: PROTOCOL_VERSION,
        session: session.id,
        resumed,
        rx_seq: session.rx_seq,
        heartbeat_ms: HEARTBEAT_MS,
      });
      await this.flush(ws);
      return;
    }

    if (!isReady(ws)) return reject(ws, "hello_required");
    const session = await this.ctx.storage.get<Session>("session");
    if (!session) return reject(ws, "no_session");

    if (msg.t === "ack") {
      if (msg.seq > session.tx_seq) return reject(ws, "bad_ack");
      if (msg.seq > session.acked_tx) {
        session.acked_tx = msg.seq;
        await this.ctx.storage.put("session", session);
      }
      await this.ctx.blockConcurrencyWhile(() => this.ackHeld(msg.seq));
      return;
    }

    // A retransmitted frame (seq already seen) is acknowledged but not processed.
    if (msg.seq > session.rx_seq) {
      session.rx_seq = msg.seq;
      await this.ctx.storage.put("session", session);
      // Only a first sight of a frame is relayed, so a retransmission cannot repeat a request.
      await this.relay(ws, msg.body);
    }
    send(ws, { t: "ack", seq: msg.seq });
  }

  // Forwards a prekey frame to the device it names. The gateway creates and stores nothing: the frame is
  // counted against the sender's allowance (limitDevice, src/ratelimit.ts) before anything is delivered,
  // then pushed to the target as an event naming the sender the gateway authenticated. A request the
  // gateway cannot deliver, or will not, is answered to the requester with a refusal, so it can wait and
  // ask again; an answer that cannot be delivered is dropped (the requester times out). Any other body
  // is ignored, as bodies were before the relay existed.
  private async relay(ws: WebSocket, body: string): Promise<void> {
    const who = (ws.deserializeAttachment() as Attachment).who;
    const frame = parseRelayFrame(body);
    if (!who || !frame || frame.to === who.device) return;
    const wait = await limitDevice(this.env, who.tenant, who.device, "prekey");
    if (wait !== null) {
      if (frame.t === "prekey_request") await this.deliver(refusedRateLimited(frame.id, frame.to, wait));
      return;
    }
    const { to, ...rest } = frame;
    const event = JSON.stringify(frame.t === "prekey_refused" ? { ...rest, from: who.device, reason: "refused" } : { ...rest, from: who.device });
    const peer = this.env.DEVICE.get(this.env.DEVICE.idFromName(`${who.tenant}:${to}`));
    const r = await peer.deliver(event);
    if (r.status !== "delivered" && frame.t === "prekey_request") await this.deliver(JSON.stringify({ t: "prekey_refused", id: frame.id, from: to, reason: "offline" }));
  }

  async webSocketClose(ws: WebSocket, code: number): Promise<void> {
    // 1005/1006 cannot be echoed in a close frame.
    ws.close(code === 1005 || code === 1006 ? 1000 : code, "closing");
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    ws.close(1011, "error");
  }

  // Test and operations introspection: counters only, never content.
  async status(): Promise<{ connected: boolean; session?: Session }> {
    const connected = this.ctx
      .getWebSockets()
      .some((s) => isOpen(s) && isReady(s));
    return { connected, session: await this.ctx.storage.get<Session>("session") };
  }
}

// What the requester is told when the gateway will not carry its prekey request: wait this long.
function refusedRateLimited(id: string, from: string, retryAfterMs: number): string {
  return JSON.stringify({ t: "prekey_refused", id, from, reason: "rate_limited", retry_after_ms: retryAfterMs });
}

function validId(v: string | null): v is string {
  return v !== null && IDENTITY.test(v);
}

// A socket with no attachment (never accepted through fetch) is not ready.
function isReady(ws: WebSocket): boolean {
  return (ws.deserializeAttachment() as Attachment | null)?.ready === true;
}

function isOpen(ws: WebSocket): boolean {
  return ws.readyState === WebSocket.READY_STATE_OPEN;
}

// Sends unless the socket has closed, which a daemon can do while a handler
// awaits storage; workerd throws on send() after close(), and that exception
// would be uncaught. Returns whether the message was sent.
function send(ws: WebSocket, m: ServerMessage): boolean {
  if (!isOpen(ws)) return false;
  ws.send(JSON.stringify(m));
  return true;
}

function reject(ws: WebSocket, code: string): void {
  send(ws, { t: "error", code });
  ws.close(CLOSE_PROTOCOL, code);
}
