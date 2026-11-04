// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Assertions parked while the Worker's /v1/connect and /a2a are closed (no device credential exists until T310,
// device connect tokens). Each one ran before the development bearer was removed; each skips with its reason and
// fails once T310 is ticked in specs/parley-mvp/tasks.md. What stays active meanwhile: the closed-door checks
// (tests/canary-acceptance.test.mjs, gateway/test/device.test.ts), the A2A and Device DO logic through the test
// shim (gateway/test/a2a*.test.ts, wire.ts), and the control-canary storage scan.

import { test } from "node:test";
import assert from "node:assert/strict";
import { taskTicked } from "./harness/pending.mjs";
import { pending } from "./harness/pending.mjs";

test("taskTicked reads the checkbox", () => {
  const md = "- [x] T301 Task\r\n- [ ] T310 Tokens\n  - [x] T3101 sub\n";
  assert.equal(taskTicked(md, "T301"), true);
  assert.equal(taskTicked(md, "T310"), false);
  assert.equal(taskTicked(md, "T3101"), true);
  assert.equal(taskTicked(md, "T999"), false);
});

pending("canary acceptance: sealed frames over the tunnel leave zero hits in storage, logs and traffic", "T310",
  "tests/canary-acceptance.test.mjs: open /v1/connect with a connect token, hello then welcome, send each of the 5 sealed frames and assert {t:'ack',seq:i+1} for each, send a malformed frame and assert an 'error' reply, then run the storage, log and traffic scans with all content canaries");
pending("canary acceptance: A2A lifecycle over POST /a2a leaves zero hits", "T310",
  "tests/canary-acceptance.test.mjs: two tunnels (caller, target); four tasks through SendMessage/CancelTask asserting states SUBMITTED, WORKING, INPUT_REQUIRED, WORKING, COMPLETED / SUBMITTED, FAILED / SUBMITTED, REJECTED / SUBMITTED, CANCELED, each relayed as an 'event' to the other side");
pending("canary acceptance: every hostile unsealed-content request is refused", "T310",
  "tests/canary-acceptance.test.mjs: for each canary field, 16 hostile SendMessage shapes plus CancelTask/GetTask/unknown-method with the canary in an id or key; assert more than 100 refusals, each an error and none a result");
pending("the Worker authenticates a connect token and routes /a2a and /v1/connect to the right Device DO", "T310",
  "gateway/test/wire.ts `gw` stands in for the Worker; replace it with SELF.fetch using a real token, and assert 401 for none/expired/other-tenant tokens and that one tenant never reaches another's device");
pending("the daemon tunnel client connects to a real gateway with a connect token", "T310",
  "internal/tunnel/worker_test.go TestAgainstWorker: run the existing hello/ack/reconnect assertions against `wrangler dev` with a token from the enrollment flow");
