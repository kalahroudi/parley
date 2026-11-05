// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109: what a tenant costs per month on Workers Paid, from per-task and per-device
// usage that comes from the measurements in specs/parley-mvp/reality-check-1.md and
// from reading gateway/src/device.ts, priced with tests/reality/pricing.json.
//   node tests/reality/cf/cost.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { estimateCost } from "../lib.mjs";

// Per task (both devices together), from the protocol: incoming WebSocket messages are
// the daemons' frames and acks. Rows written are one per accepted frame, one per
// event sent and one per event acknowledged (device.ts), plus an allowance for the
// Task DO that Phase 2 adds (state changes and the metadata audit record).
export const PER_TASK = { incomingMessages: 11, rowsWritten: 15 + 15, rowsRead: 30, awakeSeconds: 0.3 };
// Per device per month: reconnects (each is a Worker request and a DO request).
export const PER_DEVICE_MONTH = { reconnects: 120 };

export function tenantMonth({ devices, tasksPerDevicePerDay, days = 30 }, pricing) {
  const tasks = devices * tasksPerDevicePerDay * days;
  const reconnects = devices * PER_DEVICE_MONTH.reconnects;
  const usage = {
    requests: reconnects, // DO requests excluding WebSocket messages
    workerRequests: reconnects,
    wsMessages: tasks * PER_TASK.incomingMessages,
    durationSeconds: tasks * PER_TASK.awakeSeconds,
    memoryMb: 128, // billed at 128 MB regardless of use
    rowsRead: tasks * PER_TASK.rowsRead,
    rowsWritten: tasks * PER_TASK.rowsWritten,
    storageGb: 0.001 * devices / 1000, // metadata only, about 1 KB per device
  };
  return { tasks, usage, ...estimateCost(usage, pricing) };
}

// How many devices fit in the Workers Paid allowances before any overage is charged.
export function devicesBeforeOverage({ tasksPerDevicePerDay }, pricing) {
  let lo = 1, hi = 1_000_000;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (tenantMonth({ devices: mid, tasksPerDevicePerDay }, pricing).usageCost === 0) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const pricing = JSON.parse(readFileSync(new URL("../pricing.json", import.meta.url), "utf8"));
  console.log("| devices | tasks/device/day | tasks/month | billed DO requests | rows written | GB-s | usage USD | total USD (with $5 plan) |\n|---|---|---|---|---|---|---|---|");
  for (const [devices, tpd] of [[10, 20], [100, 20], [1000, 20], [1000, 100], [5000, 100]]) {
    const r = tenantMonth({ devices, tasksPerDevicePerDay: tpd }, pricing);
    console.log(`| ${devices} | ${tpd} | ${r.tasks} | ${Math.round(r.billedRequests)} | ${r.usage.rowsWritten} | ${Math.round(r.gbSeconds)} | ${r.usageCost.toFixed(2)} | ${r.total.toFixed(2)} |`);
  }
  console.log(`\nDevices before any overage at 20 tasks/device/day: ${devicesBeforeOverage({ tasksPerDevicePerDay: 20 }, pricing)}; at 100: ${devicesBeforeOverage({ tasksPerDevicePerDay: 100 }, pricing)}`);
}
