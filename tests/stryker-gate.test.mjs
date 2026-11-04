// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { bad } from "../scripts/stryker-gate.mjs";

const report = (...statuses) => ({ files: { "src/x.ts": { mutants: statuses.map((status, i) => ({ status, mutatorName: "M", location: { start: { line: i + 1 } } })) } } });

test("the Stryker gate passes only when every mutant is killed or timed out", () => {
  assert.deepEqual(bad(report("Killed", "Timeout")), []);
  for (const s of ["Survived", "NoCoverage", "RuntimeError", "CompileError", "Ignored"]) assert.equal(bad(report("Killed", s)).length, 1, s);
});
