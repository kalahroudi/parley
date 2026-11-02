// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { devicesBeforeOverage, PER_TASK, tenantMonth } from "./cost.mjs";
import pricing from "../pricing.json" with { type: "json" };

test("a small tenant stays inside the Workers Paid allowances: only the $5 plan is charged", () => {
  const r = tenantMonth({ devices: 10, tasksPerDevicePerDay: 20 }, pricing);
  assert.equal(r.tasks, 6000);
  assert.equal(r.usage.wsMessages, 6000 * PER_TASK.incomingMessages);
  assert.equal(r.usageCost, 0);
  assert.equal(r.total, 5);
});

test("incoming WebSocket messages bill 20:1 and the Worker front door is priced too", () => {
  const r = tenantMonth({ devices: 100, tasksPerDevicePerDay: 20 }, pricing);
  assert.equal(r.billedRequests, 100 * 120 + (100 * 20 * 30 * PER_TASK.incomingMessages) / 20);
  assert.ok("workerRequests" in r.parts);
});

test("overage starts where devicesBeforeOverage says, and cost grows with devices", () => {
  const n = devicesBeforeOverage({ tasksPerDevicePerDay: 100 }, pricing);
  assert.ok(n > 100 && n < 1_000_000);
  assert.equal(tenantMonth({ devices: n, tasksPerDevicePerDay: 100 }, pricing).usageCost, 0);
  assert.ok(tenantMonth({ devices: n + 1, tasksPerDevicePerDay: 100 }, pricing).usageCost > 0);
  assert.ok(tenantMonth({ devices: 5000, tasksPerDevicePerDay: 100 }, pricing).total > tenantMonth({ devices: 1000, tasksPerDevicePerDay: 100 }, pricing).total);
});
