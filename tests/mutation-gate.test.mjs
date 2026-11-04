// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { check } from "../scripts/mutation-gate.mjs";
import { check as checkStryker } from "../scripts/stryker-gate.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const read = (p) => readFileSync(join(root, p), "utf8");

const mut = (status, line = 10, type = "CONDITIONALS_NEGATION") => ({ type, status, line, column: 3 });
const result = (...mutations) => ({ files: [{ file_name: "x.go", mutations }] });
const entry = (o = {}) => ({ package: "internal/x", file: "x.go", line: 10, type: "CONDITIONALS_NEGATION", status: "LIVED", reason: "equivalent: the failure path looks the same", ...o });

test("mutation gate: only killed and not-viable mutants pass", () => {
  assert.deepEqual(check("internal/x", result(mut("KILLED"), mut("NOT VIABLE", 11)), []), []);
});

test("mutation gate: lived, timed-out and not-covered mutants fail unless allowlisted", () => {
  for (const status of ["LIVED", "TIMED OUT", "NOT COVERED"]) {
    assert.equal(check("internal/x", result(mut(status)), []).length, 1, status);
    assert.deepEqual(check("internal/x", result(mut(status)), [entry({ status })]), [], `${status} allowlisted`);
  }
});

test("mutation gate: an allowlist entry matches one exact mutant, in its own package, and needs a reason", () => {
  const lived = result(mut("LIVED"));
  assert.equal(check("internal/x", lived, [entry({ line: 11 })]).length, 1, "another line");
  assert.equal(check("internal/x", lived, [entry({ type: "ARITHMETIC_BASE" })]).length, 1, "another type");
  assert.equal(check("internal/x", lived, [entry({ file: "y.go" })]).length, 1, "another file");
  assert.equal(check("internal/x", lived, [entry({ package: "internal/y" })]).length, 1, "another package");
  assert.equal(check("internal/x", lived, [entry({ status: "NOT COVERED" })]).length, 1, "another status");
  assert.equal(check("internal/x", lived, [entry({ reason: "" })]).length, 1, "no reason");
  assert.equal(check("internal/x", lived, [entry({ reason: "meh" })]).length, 1, "a token reason");
});

test("mutation gate: a full run fails on an allowlist entry that matches nothing", () => {
  assert.equal(check("internal/x", result(mut("KILLED")), [entry()], { stale: true }).length, 1);
  assert.deepEqual(check("internal/x", result(mut("KILLED")), [entry()]), []);
  assert.deepEqual(check("internal/x", result(mut("LIVED")), [entry()], { stale: true }), []);
});

test("stryker gate: a mutant whose run crashed is not verified", () => {
  const rep = (status) => ({ files: { "src/parts.ts": { mutants: [{ status, mutatorName: "StringLiteral", location: { start: { line: 3, column: 1 } } }] } } });
  assert.deepEqual(checkStryker(rep("Killed")), []);
  assert.deepEqual(checkStryker(rep("Timeout")), []);
  for (const s of ["Survived", "NoCoverage", "RuntimeError", "CompileError", "Ignored", "Pending"]) assert.equal(checkStryker(rep(s)).length, 1, s);
  assert.equal(checkStryker({ files: {} }).length, 1, "an empty report proves nothing");
});

test("the Go mutation run enables every mutator, gates through the allowlist and has a scope for pull requests", () => {
  const sh = read("scripts/mutation.sh");
  for (const flag of ["invert-assignments", "invert-bitwise", "invert-bwassign", "invert-logical", "invert-loopctrl", "remove-self-assignments"]) {
    assert.ok(sh.includes(`--${flag}`), `mutation.sh leaves ${flag} off`);
  }
  assert.ok(!/--(arithmetic-base|conditionals-boundary|conditionals-negation|increment-decrement|invert-negatives)[ =](false|0)/.test(sh), "a default mutator is turned off");
  assert.ok(!/threshold-efficacy/.test(sh), "the efficacy floor was replaced by the allowlist gate");
  assert.ok(sh.includes("scripts/mutation-gate.mjs") && sh.includes("scripts/stryker-gate.mjs"));
  const list = JSON.parse(read("tests/coverage/mutation-allowlist.json")).go;
  const tier1 = JSON.parse(read("tests/coverage/tiers.json")).tiers["1"].packages;
  for (const a of list) {
    assert.ok(tier1.includes(a.package), `${a.package} is not a tier 1 package`);
    assert.ok(a.reason.trim().length >= 20, `${a.package}/${a.file}:${a.line} has no real reason`);
  }
});

test("CI runs mutation on changed tier 1 code per pull request and in full on main and nightly", () => {
  const ci = read(".github/workflows/ci.yml");
  assert.match(ci, /MUTATION_SCOPE: changed/);
  assert.match(ci, /scripts\/malgw-mutations\.sh/);
  const nightly = read(".github/workflows/mutation.yml");
  assert.match(nightly, /schedule:/);
  assert.match(nightly, /scripts\/mutation\.sh/);
  assert.ok(!/MUTATION_SCOPE/.test(nightly), "the nightly run must be the full one");
});
