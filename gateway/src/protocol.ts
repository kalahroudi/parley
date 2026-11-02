// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Tunnel wire protocol v1: JSON text frames between a daemon and its Device DO.
// `body` is opaque (ciphertext in later phases); the gateway never inspects it.
// The text frames "ping" and "pong" are answered by the runtime without waking
// a hibernated Durable Object.

export const PROTOCOL_VERSION = 1;
export const HEARTBEAT_MS = 20_000;
export const MAX_FRAME_BYTES = 1 << 20;

// WebSocket close codes (4000-4999 are application-defined).
export const CLOSE_PROTOCOL = 4400;
export const CLOSE_REPLACED = 4409;
export const CLOSE_TOO_LARGE = 1009;

// Daemon to gateway.
export type ClientMessage =
  | { t: "hello"; v: number; session?: string; last_rx: number }
  | { t: "frame"; seq: number; body: string }
  | { t: "ack"; seq: number };

// Gateway to daemon.
export type ServerMessage =
  | { t: "welcome"; v: number; session: string; resumed: boolean; rx_seq: number; heartbeat_ms: number }
  | { t: "ack"; seq: number }
  | { t: "event"; seq: number; body: string }
  | { t: "error"; code: string };

const isSeq = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 0;

// Returns null for anything that is not a well-formed client message.
export function parseClientMessage(raw: string): ClientMessage | null {
  let m: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return null;
    m = parsed as Record<string, unknown>;
  } catch {
    return null;
  }
  switch (m.t) {
    case "hello":
      if (m.v !== PROTOCOL_VERSION || !isSeq(m.last_rx)) return null;
      if (m.session !== undefined && (typeof m.session !== "string" || m.session.length > 64)) return null;
      return { t: "hello", v: m.v, session: m.session, last_rx: m.last_rx };
    case "frame":
      if (!isSeq(m.seq) || m.seq === 0 || typeof m.body !== "string") return null;
      return { t: "frame", seq: m.seq, body: m.body };
    case "ack":
      return isSeq(m.seq) ? { t: "ack", seq: m.seq } : null;
    default:
      return null;
  }
}

const utf8 = new TextEncoder();

// Size in bytes on the wire (UTF-16 length undercounts non-ASCII text).
export const byteLength = (s: string): number => utf8.encode(s).byteLength;
