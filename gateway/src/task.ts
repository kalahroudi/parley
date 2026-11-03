// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { DurableObject } from "cloudflare:workers";
import type { Env } from "./index";

export const TASK_TTL_DEFAULT_MS = 15 * 60_000;
export const TASK_TTL_MAX_MS = 24 * 3600_000;
export const TASK_METADATA_RETENTION_MS = 90 * 24 * 3600_000;

export type TaskState = "SUBMITTED" | "WORKING" | "INPUT_REQUIRED" | "COMPLETED" | "FAILED" | "CANCELED" | "REJECTED";
export type Actor = "caller" | "target";

// What an actor asks for. The gateway only sees the plaintext state code, which
// is a hint: the authoritative state is the signed message inside the
// ciphertext, checked by the daemons. CANCEL and REPLY come from the caller;
// the rest from the target.
export type TaskEvent = "WORKING" | "INPUT_REQUIRED" | "COMPLETED" | "FAILED" | "REJECTED" | "CANCEL" | "REPLY";

export const TERMINAL: ReadonlySet<TaskState> = new Set(["COMPLETED", "FAILED", "CANCELED", "REJECTED"]);

// Allowed moves. A terminal state has none, so nothing (a late reply included)
// is accepted after CANCEL, FAILED, COMPLETED or REJECTED.
const NEXT: Record<TaskState, readonly TaskState[]> = {
  SUBMITTED: ["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "CANCELED", "REJECTED"],
  WORKING: ["INPUT_REQUIRED", "COMPLETED", "FAILED", "CANCELED"],
  INPUT_REQUIRED: ["WORKING", "COMPLETED", "FAILED", "CANCELED"],
  COMPLETED: [],
  FAILED: [],
  CANCELED: [],
  REJECTED: [],
};

const TARGET_EVENTS: ReadonlySet<TaskEvent> = new Set(["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "REJECTED"]);

// Metadata only: no content, no keys.
export interface TaskRecord {
  id: string;
  caller: string; // device ids
  target: string;
  state: TaskState;
  seq: number; // highest message sequence accepted
  created: number;
  updated: number;
  expires_at: number;
  reason?: "expired" | "canceled" | "target" | "disconnected";
}

export type CreateError = "bad_request" | "exists";
export type ApplyError = "not_found" | "forbidden" | "bad_seq" | "bad_transition" | "terminal";

const ID = /^[A-Za-z0-9_-]{1,64}$/;

// One Task DO per task (named `${tenant}:${task id}`). It owns the lifecycle
// state machine and the expiry deadline. It stores routing metadata only; task
// ciphertext is never stored here (retention modes arrive in T304).
export class Task extends DurableObject<Env> {
  async create(input: { id: string; caller: string; target: string; ttl_ms?: number }): Promise<TaskRecord | CreateError> {
    const ttl = input.ttl_ms ?? TASK_TTL_DEFAULT_MS;
    if (![input.id, input.caller, input.target].every((s) => typeof s === "string" && ID.test(s))) return "bad_request";
    if (!Number.isFinite(ttl) || ttl <= 0 || ttl > TASK_TTL_MAX_MS) return "bad_request";
    return this.ctx.blockConcurrencyWhile(async () => {
      if (await this.ctx.storage.get("task")) return "exists";
      const now = Date.now();
      const rec: TaskRecord = {
        id: input.id,
        caller: input.caller,
        target: input.target,
        state: "SUBMITTED",
        seq: 0,
        created: now,
        updated: now,
        expires_at: now + ttl,
      };
      await this.ctx.storage.put("task", rec);
      await this.ctx.storage.setAlarm(rec.expires_at);
      return rec;
    });
  }

  // Applies one event from `actor` with its message sequence number. Sequence
  // numbers must strictly increase, so a replayed or reordered hint is refused.
  async apply(actor: Actor, device: string, event: TaskEvent, seq: number): Promise<TaskRecord | ApplyError> {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.load();
      if (!rec) return "not_found";
      if (device !== (actor === "caller" ? rec.caller : rec.target)) return "forbidden";
      const allowed = actor === "target" ? TARGET_EVENTS.has(event) : event === "CANCEL" || event === "REPLY";
      if (!allowed) return "forbidden";
      if (TERMINAL.has(rec.state)) return "terminal";
      if (!Number.isSafeInteger(seq) || seq <= rec.seq) return "bad_seq";
      const to: TaskState = event === "CANCEL" ? "CANCELED" : event === "REPLY" ? "WORKING" : event;
      // A reply answers a question; it is not valid in any other state.
      if (event === "REPLY" && rec.state !== "INPUT_REQUIRED") return "bad_transition";
      if (!NEXT[rec.state].includes(to)) return "bad_transition";
      return this.move(rec, to, seq, event === "CANCEL" ? "canceled" : TERMINAL.has(to) ? "target" : undefined);
    });
  }

  // The caller's socket dropped in Strict mode: the task fails.
  async callerDisconnected(): Promise<TaskRecord | "not_found"> {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.load();
      if (!rec) return "not_found";
      return TERMINAL.has(rec.state) ? rec : this.move(rec, "FAILED", rec.seq, "disconnected");
    });
  }

  async get(): Promise<TaskRecord | null> {
    return this.ctx.blockConcurrencyWhile(() => this.load());
  }

  // Fires at the expiry deadline, then at the end of metadata retention.
  async alarm(): Promise<void> {
    await this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.load(); // expires a due task
      if (!rec) return;
      // Fired early (still live): keep the expiry deadline armed, not the purge.
      if (!TERMINAL.has(rec.state)) return this.ctx.storage.setAlarm(rec.expires_at);
      const purge = rec.updated + TASK_METADATA_RETENTION_MS;
      if (purge <= Date.now()) await this.ctx.storage.deleteAll();
      else await this.ctx.storage.setAlarm(purge);
    });
  }

  // Reads the record, lazily expiring it if the alarm has not run yet, so a read
  // can never show a live state past the deadline.
  private async load(): Promise<TaskRecord | null> {
    const rec = await this.ctx.storage.get<TaskRecord>("task");
    if (!rec) return null;
    if (!TERMINAL.has(rec.state) && rec.expires_at <= Date.now()) return this.move(rec, "FAILED", rec.seq, "expired");
    return rec;
  }

  private async move(rec: TaskRecord, to: TaskState, seq: number, reason?: TaskRecord["reason"]): Promise<TaskRecord> {
    rec.state = to;
    rec.seq = seq;
    rec.updated = Date.now();
    if (reason) rec.reason = reason;
    await this.ctx.storage.put("task", rec);
    if (TERMINAL.has(to)) await this.ctx.storage.setAlarm(rec.updated + TASK_METADATA_RETENTION_MS);
    return rec;
  }
}
