// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { DurableObject } from "cloudflare:workers";
import type { Env } from "./index";

export const TASK_TTL_DEFAULT_MS = 15 * 60_000;
export const TASK_TTL_MAX_MS = 24 * 3600_000;
export const TASK_METADATA_RETENTION_MS = 90 * 24 * 3600_000;

export type TaskState = "SUBMITTED" | "WORKING" | "INPUT_REQUIRED" | "COMPLETED" | "FAILED" | "CANCELED" | "REJECTED";
export type Role = "caller" | "target";

// What a device asks for. The gateway only sees the plaintext state code, which
// is a hint: the authoritative state is the signed message inside the
// ciphertext, checked by the daemons. CANCEL and REPLY come from the caller;
// the rest from the target.
export type TaskEvent = "WORKING" | "INPUT_REQUIRED" | "COMPLETED" | "FAILED" | "REJECTED" | "CANCEL" | "REPLY";

export const TERMINAL: ReadonlySet<TaskState> = new Set(["COMPLETED", "FAILED", "CANCELED", "REJECTED"]);

// Allowed moves. A terminal state has none, so nothing (a late reply included)
// is accepted after CANCEL, FAILED, COMPLETED or REJECTED.
export const NEXT: Readonly<Record<TaskState, readonly TaskState[]>> = {
  SUBMITTED: ["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "CANCELED", "REJECTED"],
  WORKING: ["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "CANCELED"], // WORKING again is a progress update
  INPUT_REQUIRED: ["WORKING", "COMPLETED", "FAILED", "CANCELED"],
  COMPLETED: [],
  FAILED: [],
  CANCELED: [],
  REJECTED: [],
};

const ROLE_EVENTS: Readonly<Record<Role, ReadonlySet<string>>> = {
  caller: new Set(["CANCEL", "REPLY"]),
  target: new Set(["WORKING", "INPUT_REQUIRED", "COMPLETED", "FAILED", "REJECTED"]),
};

// Metadata only (ids, states, counters, timestamps): no content, no keys.
export interface TaskRecord {
  id: string;
  tenant: string;
  caller: string; // device ids
  target: string;
  state: TaskState;
  // Highest message sequence accepted from each sender. Each sender numbers its
  // own messages (the signed transcript and the replay table are per sender).
  caller_seq: number;
  target_seq: number;
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
// ciphertext is never stored here (retention modes arrive in T304). Every
// method names the tenant and answers "not_found" for another tenant's task.
// All state is in storage, so a restart or hibernation loses nothing.
export class Task extends DurableObject<Env> {
  async create(input: { tenant: string; id: string; caller: string; target: string; ttl_ms?: number }): Promise<TaskRecord | CreateError> {
    const ttl = input.ttl_ms ?? TASK_TTL_DEFAULT_MS;
    if (![input.tenant, input.id, input.caller, input.target].every((s) => typeof s === "string" && ID.test(s))) return "bad_request";
    if (input.caller === input.target) return "bad_request"; // one device could otherwise act in both roles
    if (!Number.isSafeInteger(ttl) || ttl <= 0 || ttl > TASK_TTL_MAX_MS) return "bad_request";
    return this.ctx.blockConcurrencyWhile(async () => {
      if (await this.ctx.storage.get("task")) return "exists";
      const now = Date.now();
      const rec: TaskRecord = {
        id: input.id,
        tenant: input.tenant,
        caller: input.caller,
        target: input.target,
        state: "SUBMITTED",
        caller_seq: 0,
        target_seq: 0,
        created: now,
        updated: now,
        expires_at: now + ttl,
      };
      await this.save(rec, rec.expires_at);
      return rec;
    });
  }

  // Applies one event from `device` with its message sequence number. The role
  // is the device's place in this task, never a claim by the request. Sequence
  // numbers must strictly increase per sender, so a replayed or reordered hint
  // is refused.
  async apply(tenant: string, device: string, event: TaskEvent, seq: number): Promise<TaskRecord | ApplyError> {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.open(tenant);
      if (!rec) return "not_found";
      const role: Role | null = device === rec.caller ? "caller" : device === rec.target ? "target" : null;
      if (!role || !ROLE_EVENTS[role].has(event)) return "forbidden";
      if (TERMINAL.has(rec.state)) return "terminal";
      const last = rec[`${role}_seq`];
      if (!Number.isSafeInteger(seq) || seq <= last) return "bad_seq";
      const to: TaskState = event === "CANCEL" ? "CANCELED" : event === "REPLY" ? "WORKING" : (event as TaskState);
      // A reply answers a question; it is not valid in any other state.
      if (event === "REPLY" && rec.state !== "INPUT_REQUIRED") return "bad_transition";
      if (!NEXT[rec.state].includes(to)) return "bad_transition";
      rec[`${role}_seq`] = seq;
      return this.move(rec, to, Date.now(), event === "CANCEL" ? "canceled" : TERMINAL.has(to) ? "target" : undefined);
    });
  }

  // The caller's socket dropped in Strict mode: the task fails.
  async callerDisconnected(tenant: string, device: string): Promise<TaskRecord | "not_found" | "forbidden"> {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.open(tenant);
      if (!rec) return "not_found";
      if (device !== rec.caller) return "forbidden";
      return TERMINAL.has(rec.state) ? rec : this.move(rec, "FAILED", Date.now(), "disconnected");
    });
  }

  async get(tenant: string): Promise<TaskRecord | null> {
    return this.ctx.blockConcurrencyWhile(() => this.open(tenant));
  }

  // Fires at the expiry deadline, then at the end of metadata retention. Safe to
  // deliver any number of times, early or late: it only reads the clock and the
  // record, and arms the one alarm that is due next.
  async alarm(): Promise<void> {
    await this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.load(); // expires a due task
      if (!rec) return;
      if (!TERMINAL.has(rec.state)) return this.ctx.storage.setAlarm(rec.expires_at); // fired early
      const purge = rec.updated + TASK_METADATA_RETENTION_MS;
      if (purge <= Date.now()) await this.ctx.storage.deleteAll();
      else await this.ctx.storage.setAlarm(purge);
    });
  }

  private async open(tenant: string): Promise<TaskRecord | null> {
    const rec = await this.load();
    return rec && rec.tenant === tenant ? rec : null;
  }

  // Reads the record, lazily expiring it if the alarm has not run yet, so a read
  // can never show a live state past the deadline. The expiry is stamped at the
  // deadline, not at the read, so the retention clock is the same either way.
  private async load(): Promise<TaskRecord | null> {
    const rec = await this.ctx.storage.get<TaskRecord>("task");
    if (!rec) return null;
    if (!TERMINAL.has(rec.state) && rec.expires_at <= Date.now()) return this.move(rec, "FAILED", rec.expires_at, "expired");
    return rec;
  }

  // `updated` never goes backwards, whatever the clock does.
  private async move(rec: TaskRecord, to: TaskState, at: number, reason?: TaskRecord["reason"]): Promise<TaskRecord> {
    rec.state = to;
    rec.updated = Math.max(rec.updated, at);
    if (reason) rec.reason = reason;
    await this.save(rec, TERMINAL.has(to) ? rec.updated + TASK_METADATA_RETENTION_MS : rec.expires_at);
    return rec;
  }

  // The record and its alarm are written with no await between them, so storage
  // commits them together: a task is never left without the alarm that ends it.
  private async save(rec: TaskRecord, alarmAt: number): Promise<void> {
    const put = this.ctx.storage.put("task", rec);
    const alarm = this.ctx.storage.setAlarm(alarmAt);
    await Promise.all([put, alarm]);
  }
}
