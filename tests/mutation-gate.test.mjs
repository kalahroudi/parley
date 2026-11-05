// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { RUNNERS, built, check, owned } from "../scripts/mutation-gate.mjs";
import { check as checkStryker } from "../scripts/stryker-gate.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const read = (p) => readFileSync(join(root, p), "utf8");

const mut = (status, line = 10, type = "CONDITIONALS_NEGATION") => ({ type, status, line, column: 3 });
const result = (...mutations) => ({ files: [{ file_name: "x.go", mutations }] });
const entry = (o = {}) => ({ package: "internal/x", file: "x.go", line: 10, type: "CONDITIONALS_NEGATION", status: "LIVED", reason: "equivalent: the failure path looks the same", ...o });

test("mutation gate: only killed and not-viable mutants pass", () => {
  assert.deepEqual(check("internal/x", result(mut("KILLED"), mut("NOT VIABLE", 11)), []), []);
});

test("mutation gate: a timed-out mutant is detected (the tests hung on it), so it passes", () => {
  assert.deepEqual(check("internal/x", result(mut("TIMED OUT")), []), []);
});

test("mutation gate: lived and not-covered mutants fail unless allowlisted", () => {
  for (const status of ["LIVED", "NOT COVERED"]) {
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
  assert.deepEqual(checkStryker(rep("Killed"), ["src/parts.ts"]), []);
  assert.equal(checkStryker(rep("Killed"), ["src/parts.ts", "src/device.ts"]).length, 1, "a file that was asked for and not mutated is not clean");
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

const [linux, darwin, windows] = RUNNERS;

test("mutation gate: each Go file is judged on the runner that builds it, OS-specific code on its own OS", () => {
  assert.deepEqual([...owned("internal/binding", linux)].sort(), ["binding.go", "lock_unix.go", "store.go", "syncdir_unix.go"]);
  assert.deepEqual([...owned("internal/binding", windows)].sort(), ["lock_windows.go", "syncdir_windows.go"]);
  assert.deepEqual([...owned("internal/prekey", windows)].sort(), ["harden_windows.go", "mem_windows.go"]);
  assert.ok(owned("internal/prekey", darwin).has("harden_other.go"));
  for (const f of owned("internal/binding", windows)) assert.ok(!owned("internal/binding", linux).has(f));
});

// Files that no runner builds have nothing for a runner to mutate. Each is listed with why.
const UNBUILT = { "internal/prekey/scrub_other.go": "a function with an empty body (for architectures other than amd64 and arm64): no statement to cover or mutate" };

test("mutation gate: every tier 1 Go file is owned by exactly one runner, bar the reviewed exceptions", () => {
  const tiers = JSON.parse(read("tests/coverage/tiers.json")).tiers["1"].packages;
  for (const pkg of tiers) {
    const files = readdirSync(join(root, pkg)).filter((f) => f.endsWith(".go") && !f.endsWith("_test.go"));
    for (const f of files) {
      const owners = RUNNERS.filter((r) => owned(pkg, r, root).has(f));
      if (UNBUILT[`${pkg}/${f}`]) {
        assert.equal(owners.length, 0, `${pkg}/${f} is built somewhere now: drop it from UNBUILT`);
        assert.ok(!RUNNERS.some((r) => built(pkg, r, root).has(f)));
      } else assert.equal(owners.length, 1, `${pkg}/${f} is owned by ${owners.length} runners`);
    }
  }
});

test("mutation gate: on a runner, other OSes' files are skipped but every owned mutant must still be killed", () => {
  const res = { files: [{ file_name: "lock_windows.go", mutations: [mut("NOT COVERED")] }, { file_name: "store.go", mutations: [mut("NOT COVERED", 20)] }] };
  const own = owned("internal/binding", linux, root);
  assert.deepEqual(check("internal/binding", res, [], { own }), ["NOT COVERED CONDITIONALS_NEGATION at internal/binding/store.go:20:3"]);
  const win = owned("internal/binding", windows, root);
  assert.deepEqual(check("internal/binding", res, [], { own: win }), ["NOT COVERED CONDITIONALS_NEGATION at internal/binding/lock_windows.go:10:3"]);
  // An allowlist entry for a file this runner does not own is neither used nor stale here.
  const stale = [entry({ package: "internal/binding", file: "lock_windows.go", status: "NOT COVERED" })];
  assert.deepEqual(check("internal/binding", { files: [] }, stale, { stale: true, own }), []);
});
