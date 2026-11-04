// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
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

// Security-critical packages named by the plan's tier 1 row; moving one down a tier needs the plan to change.
test("security-critical packages are in tier 1", () => {
  for (const p of ["internal/binding", "internal/envelope", "internal/revocation", "internal/logx", "internal/prekey", "internal/replay", "internal/receive"]) {
    assert.ok(tiers["1"].packages.includes(p), `${p} must be tier 1`);
  }
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

// Tier 1 for TypeScript: the task state machine, deadlines and retention logic.
// Each listed file needs a 100% gate in vitest (no exclusions) and a Stryker run
// that must kill every mutant; this test fails if either is dropped or if the
// file stops being listed.
test("gateway tier 1 files are gated at 100% and mutation tested, with no exclusions", () => {
  const files = JSON.parse(read("tests/coverage/gateway-tier1.json")).files;
  assert.ok(files.includes("gateway/src/task.ts"), "the task state machine is tier 1");
  const cfg = read("gateway/vitest.config.ts");
  const stryker = JSON.parse(read("gateway/stryker.config.json"));
  assert.equal(stryker.thresholds.break, 100);
  for (const f of files) {
    const src = f.replace(/^gateway\//, "");
    assert.ok(existsSync(join(root, f)), `${f} does not exist`);
    assert.ok(
      cfg.includes(`"${src}": { lines: 100, statements: 100, branches: 100, functions: 100 }`),
      `vitest.config.ts has no 100% gate for ${src}`,
    );
    assert.ok(stryker.mutate.includes(src), `stryker.config.json does not mutate ${src}`);
    assert.ok(!cfg.split("exclude:")[1]?.split("\n")[0].includes(src), `${src} is excluded from coverage`);
    assert.ok(!/istanbul ignore|c8 ignore|Stryker disable/.test(read(f)), `${f} carries a coverage or mutation exclusion`);
    assert.ok(!/console\.|\blogx?\b/.test(read(f)), `${f} logs; the Task DO stores and emits metadata only`);
  }
  assert.match(read("gateway/package.json"), /"test:mutation": "stryker run"/);
  assert.ok(read("scripts/mutation.sh").includes("stryker run"), "mutation.sh does not run the gateway mutation tests");
  assert.ok(!stryker.mutate.some((m) => m.startsWith("!")), "no mutation exclusions");
});

// The cover profile has no statements for assembly; tests/coverage/README.md says what covers it instead.
test("every assembly file in a tier 1 package has tests beside it and is documented", () => {
  const doc = read("tests/coverage/README.md");
  for (const p of tiers["1"].packages) {
    const names = readdirSync(join(root, p));
    for (const asm of names.filter((n) => n.endsWith(".s"))) {
      const stem = asm.slice(0, -2);
      assert.ok(names.includes(`${stem}_test.go`), `${p}/${asm} has no ${stem}_test.go`);
      assert.ok(doc.includes(asm.replace(/\.s$/, "")) || doc.includes("scrub_*.s"), `${asm} is not covered by the coverage README`);
    }
  }
});
