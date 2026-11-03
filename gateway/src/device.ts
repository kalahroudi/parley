// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { DurableObject } from "cloudflare:workers";
import type { Env } from "./index";
import {
  CLOSE_PROTOCOL,
  CLOSE_REPLACED,
  CLOSE_TOO_LARGE,
  HEARTBEAT_MS,
  MAX_FRAME_BYTES,
  PROTOCOL_VERSION,
  byteLength,
  parseClientMessage,
  type ServerMessage,
} from "./protocol";

// Per-connection state, kept in the socket attachment so it survives hibernation.
interface Attachment {
  ready: boolean;
}

// Session counters, kept in storage so a resume survives eviction. Metadata only.
interface Session {
  id: string;
  rx_seq: number; // highest daemon frame seq accepted
  tx_seq: number; // last event seq sent to the daemon
  acked_tx: number; // highest event seq the daemon acknowledged
}

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
    pair[1].serializeAttachment({ ready: false } satisfies Attachment);
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
      ws.serializeAttachment({ ready: true } satisfies Attachment);
      send(ws, {
        t: "welcome",
        v: PROTOCOL_VERSION,
        session: session.id,
        resumed,
        rx_seq: session.rx_seq,
        heartbeat_ms: HEARTBEAT_MS,
      });
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
      return;
    }

    // A retransmitted frame (seq already seen) is acknowledged but not processed.
    if (msg.seq > session.rx_seq) {
      session.rx_seq = msg.seq;
      await this.ctx.storage.put("session", session);
      // Routing to the Task DO arrives with the task state machine (Phase 2).
    }
    send(ws, { t: "ack", seq: msg.seq });
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
