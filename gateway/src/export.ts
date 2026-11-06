// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// The metadata audit CSV. Only metadata exists to export: ids, owners, states, times and size buckets (plus the
// plaintext group, card and owner names the spec already declares plaintext). Cells can carry text a user chose
// (an owner address, a group name), and a spreadsheet runs a cell that starts with = + - @ as a formula, so every
// cell is neutralized before it is written.

import type { AuditEvent } from "./tenant";

// A cell a spreadsheet would read as a formula (or, with a tab or carriage return first, hide one behind) gets a
// leading apostrophe, then RFC 4180 quoting where the text needs it.
export function csvCell(v: string | number | undefined): string {
  let s = v === undefined ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export const csvRow = (cells: readonly (string | number | undefined)[]): string => `${cells.map(csvCell).join(",")}\r\n`;

const iso = (ms: number | undefined) => (ms === undefined ? undefined : new Date(ms).toISOString());

export const ADMIN_COLUMNS = ["time", "action", "actor", "subject", "detail"] as const;
export const TASK_COLUMNS = [
  "created",
  "task_id",
  "caller_owner",
  "caller_device",
  "target_owner",
  "target_device",
  "state",
  "reason",
  "updated",
  "size_bucket",
  "retention",
  "expires_at",
  "ciphertext_deleted_at",
] as const;

// `detail` is a small map of counts and names; it is written as `key=value` pairs, sorted by key.
export function adminRow(e: AuditEvent): string {
  const d = e.detail ?? {};
  const detail = Object.keys(d)
    .sort()
    .map((k) => `${k}=${d[k]}`)
    .join(";");
  return csvRow([iso(e.at), e.action, e.actor, e.subject, detail]);
}

// What the CSV says about one task: the facts the tenant noted when it began, and the state the Task DO holds now
// (`state` undefined once that record has been purged).
export interface TaskAudit {
  created: number;
  task: string;
  caller: string;
  target: string;
  bucket: number;
  retention: string;
  expires_at: number;
  state?: string;
  reason?: string;
  updated?: number;
  ciphertext_deleted_at?: number;
}

export function taskRow(t: TaskAudit, owner: (device: string) => string | undefined): string {
  return csvRow([
    iso(t.created),
    t.task,
    owner(t.caller),
    t.caller,
    owner(t.target),
    t.target,
    t.state ?? "PURGED",
    t.reason,
    iso(t.updated),
    t.bucket,
    t.retention,
    iso(t.expires_at),
    iso(t.ciphertext_deleted_at),
  ]);
}
