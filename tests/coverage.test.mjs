// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const read = (p) => readFileSync(join(root, p), "utf8");
const tiers = JSON.parse(read("tests/coverage/tiers.json")).tiers;

// The numbers are the plan's coverage policy (specs/parley-mvp/plan.md); lowering
// one here needs the plan to change first.
test("tier gates match the plan's coverage policy", () => {
  assert.deepEqual(Object.keys(tiers).sort(), ["1", "2", "3"]);
  assert.equal(tiers["1"].line, 100);
  assert.equal(tiers["2"].line, 95);
  assert.equal(tiers["3"].line, 85);
});

test("every tiered package exists, and none is in two tiers", () => {
  const seen = new Map();
  for (const [tier, t] of Object.entries(tiers)) {
    for (const p of t.packages) {
      assert.ok(existsSync(join(root, p)), `${p} (tier ${tier}) does not exist`);
      assert.equal(seen.get(p), undefined, `${p} is in tiers ${seen.get(p)} and ${tier}`);
      seen.set(p, tier);
    }
  }
});

test("the gateway enforces tier 2 per file, 95% lines and 90% branches", () => {
  const cfg = read("gateway/vitest.config.ts");
  assert.match(cfg, /perFile: true/);
  assert.match(cfg, /lines: 95/);
  assert.match(cfg, /branches: 90/);
  const pkg = JSON.parse(read("gateway/package.json")).scripts;
  assert.match(pkg["test:coverage"], /--coverage/);
  assert.match(pkg["test:oidc-coverage"], /--test-coverage-lines=95/);
  assert.match(pkg["test:oidc-coverage"], /--test-coverage-branches=90/);
});

test("CI and make run the gates", () => {
  const ci = read(".github/workflows/ci.yml");
  for (const step of ["scripts/covergate", "npm run test:coverage", "npm run test:oidc-coverage", "scripts/mutation.sh"]) {
    assert.ok(ci.includes(step), `ci.yml lacks ${step}`);
  }
  const mk = read("Makefile");
  for (const step of ["scripts/covergate", "npm run test:coverage", "scripts/mutation.sh"]) {
    assert.ok(mk.includes(step), `Makefile lacks ${step}`);
  }
});
