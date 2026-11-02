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

export type DeliverResult = { status: "delivered"; seq: number } | { status: "offline" };

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
    // A new connection supersedes the old one (the daemon reconnected).
    for (const old of this.ctx.getWebSockets()) {
      old.serializeAttachment({ ready: false } satisfies Attachment);
      old.close(CLOSE_REPLACED, "replaced");
    }
    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1]);
    pair[1].serializeAttachment({ ready: false } satisfies Attachment);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  // Pushes an opaque event to the connected daemon.
  async deliver(body: string): Promise<DeliverResult> {
    const ws = this.ctx.getWebSockets().find((s) => (s.deserializeAttachment() as Attachment | null)?.ready);
    const session = await this.ctx.storage.get<Session>("session");
    if (!ws || !session) return { status: "offline" };
    session.tx_seq += 1;
    await this.ctx.storage.put("session", session);
    send(ws, { t: "event", seq: session.tx_seq, body });
    return { status: "delivered", seq: session.tx_seq };
  }

  async webSocketMessage(ws: WebSocket, data: string | ArrayBuffer): Promise<void> {
    if (typeof data !== "string") return ws.close(CLOSE_PROTOCOL, "text frames only");
    if (data.length > MAX_FRAME_BYTES) return ws.close(CLOSE_TOO_LARGE, "frame too large");
    const msg = parseClientMessage(data);
    if (!msg) return reject(ws, "bad_message");
    const att = (ws.deserializeAttachment() as Attachment | null) ?? { ready: false };

    if (msg.t === "hello") {
      if (att.ready) return reject(ws, "duplicate_hello");
      const stored = await this.ctx.storage.get<Session>("session");
      const resumed = !!stored && !!msg.session && stored.id === msg.session;
      const session: Session = resumed
        ? stored
        : { id: crypto.randomUUID(), rx_seq: 0, tx_seq: 0, acked_tx: 0 };
      // Events the daemon says it received count as acknowledged.
      session.acked_tx = Math.max(session.acked_tx, Math.min(msg.last_rx, session.tx_seq));
      await this.ctx.storage.put("session", session);
      ws.serializeAttachment({ ready: true } satisfies Attachment);
      return send(ws, {
        t: "welcome",
        v: PROTOCOL_VERSION,
        session: session.id,
        resumed,
        rx_seq: session.rx_seq,
        heartbeat_ms: HEARTBEAT_MS,
      });
    }

    if (!att.ready) return reject(ws, "hello_required");
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
      .some((s) => (s.deserializeAttachment() as Attachment | null)?.ready);
    return { connected, session: await this.ctx.storage.get<Session>("session") };
  }
}

function send(ws: WebSocket, m: ServerMessage): void {
  ws.send(JSON.stringify(m));
}

function reject(ws: WebSocket, code: string): void {
  send(ws, { t: "error", code });
  ws.close(CLOSE_PROTOCOL, code);
}
