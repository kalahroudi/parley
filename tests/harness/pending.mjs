// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Named pending tests, the Node twin of `pending` in internal/acceptance: a test that cannot be written until a
// task is built. It skips with the reason while the task is open and FAILS once tasks.md ticks the task, so a
// ticked task cannot leave its acceptance test unwritten.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(import.meta.url), "..", "..", "..");

export function taskTicked(md, task) {
  return md.replace(/\r/g, "").split("\n").some((l) => l.trim().startsWith(`- [x] ${task} `));
}

export function pending(name, task, reason) {
  test(`pending ${task}: ${name}`, (t) => {
    const md = readFileSync(join(root, "specs", "parley-mvp", "tasks.md"), "utf8");
    if (taskTicked(md, task)) assert.fail(`${task} is ticked but this acceptance test is still pending: write it (${reason})`);
    t.skip(`pending ${task}: ${reason}`);
  });
}
