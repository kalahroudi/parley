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

// Prekey relay (T412). A caller asks a target for a one-time prekey, and the target answers, through the
// gateway, which only forwards: it never creates, stores, or reads a prekey (the blob is opaque, signed by
// the target). Frames are small JSON bodies inside tunnel frames. A daemon names the other end in `to`; the
// gateway rewrites that into `from` with the sender it authenticated, so a daemon never trusts a claimed
// sender, and the target still checks the caller itself. internal/frames (Go) is the other side.
export const MAX_RELAY_BYTES = 4096;
const RELAY_ID = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_NONCE_BYTES = 32;
const MAX_PREKEY_BYTES = 1024;

export type RelayFrame =
  | { t: "prekey_request"; id: string; to: string; nonce: string; expires_at: number }
  | { t: "prekey_reply"; id: string; to: string; prekey: string }
  | { t: "prekey_refused"; id: string; to: string };

// The decoded size of canonical standard base64 (what btoa writes), or null when the text is anything else.
function b64Size(s: unknown, max: number): number | null {
  if (typeof s !== "string" || s.length === 0 || s.length > Math.ceil(max / 3) * 4) return null;
  try {
    const bin = atob(s);
    return btoa(bin) === s && bin.length <= max ? bin.length : null;
  } catch {
    return null;
  }
}

const hasOnly = (m: Record<string, unknown>, ...keys: string[]) =>
  Object.keys(m).length === keys.length && keys.every((k) => k in m);

// Returns null for anything that is not exactly one of the three frames: unknown keys, odd ids, text that is
// not canonical base64, or a body over MAX_RELAY_BYTES.
export function parseRelayFrame(body: string): RelayFrame | null {
  if (body.length > MAX_RELAY_BYTES) return null;
  let m: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(body);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    m = parsed as Record<string, unknown>;
  } catch {
    return null;
  }
  const ids = typeof m.id === "string" && RELAY_ID.test(m.id) && typeof m.to === "string" && RELAY_ID.test(m.to);
  if (!ids) return null;
  const id = m.id as string;
  const to = m.to as string;
  switch (m.t) {
    case "prekey_request":
      if (!hasOnly(m, "t", "id", "to", "nonce", "expires_at") || b64Size(m.nonce, MAX_NONCE_BYTES) === null || !Number.isSafeInteger(m.expires_at) || (m.expires_at as number) <= 0) return null;
      return { t: "prekey_request", id, to, nonce: m.nonce as string, expires_at: m.expires_at as number };
    case "prekey_reply":
      if (!hasOnly(m, "t", "id", "to", "prekey") || b64Size(m.prekey, MAX_PREKEY_BYTES) === null) return null;
      return { t: "prekey_reply", id, to, prekey: m.prekey as string };
    case "prekey_refused":
      return hasOnly(m, "t", "id", "to") ? { t: "prekey_refused", id, to } : null;
    default:
      return null;
  }
}
