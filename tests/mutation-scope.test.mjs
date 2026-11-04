// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { select } from "../scripts/mutation-scope.mjs";

const pkgs = ["internal/binding", "internal/envelope"];
const files = ["gateway/src/task.ts", "gateway/src/device.ts", "gateway/src/acl.ts"];
const sh = (cwd, ...a) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", ...a], { cwd, stdio: "pipe", encoding: "utf8" });

// A repo with `main` holding the base, and a branch `pr` that applies `change` on top of it.
function fixture(change) {
  const dir = mkdtempSync(join(tmpdir(), "parley-scope-"));
  const put = (f, c) => {
    mkdirSync(dirname(join(dir, f)), { recursive: true });
    writeFileSync(join(dir, f), c);
  };
  sh(dir, "init", "-q", "-b", "main");
  for (const f of ["internal/binding/b.go", "internal/envelope/e.go", "gateway/src/task.ts", "gateway/src/device.ts", "gateway/src/acl.ts", "gateway/test/task.test.ts", "gateway/test/a2a.test.ts", "gateway/test/wire.ts", "README.md"]) put(f, "base");
  put("gateway/test/a2a.test.ts", 'import "../src/task";');
  put("gateway/test/task.test.ts", 'import "../src/task";');
  sh(dir, "add", "-A");
  sh(dir, "commit", "-qm", "base");
  sh(dir, "checkout", "-qb", "pr");
  change(put, dir);
  sh(dir, "add", "-A");
  sh(dir, "commit", "-qm", "change");
  return { dir, put, done: () => rmSync(dir, { recursive: true, force: true }) };
}
const pick = (change, extra = {}) => {
  const f = fixture(change);
  try {
    return select({ scope: "changed", base: "main", pkgs, files, cwd: f.dir, ...extra });
  } finally {
    f.done();
  }
};

test("mutation scope: only the tier 1 code a change touches, plus code whose tests changed", () => {
  const r = pick((put) => put("internal/binding/b.go", "new"));
  assert.deepEqual([r.scope, r.packages, r.files], ["changed", ["internal/binding"], []]);
  // A test file of a Go package is inside its directory; a gateway test counts for every tier 1 file it imports,
  // not only the one with the same name (a2a.test.ts kills task.ts mutants).
  assert.deepEqual(pick((put) => put("gateway/test/a2a.test.ts", 'import "../src/task"; // x')).files, ["gateway/src/task.ts"]);
  assert.deepEqual(pick((put) => put("gateway/src/acl.ts", "new")).files, ["gateway/src/acl.ts"]);
  assert.deepEqual(pick((put) => put("README.md", "docs")).files, []);
});

test("mutation scope: a shared test helper or an unreadable test means every file", () => {
  assert.deepEqual(pick((put) => put("gateway/test/wire.ts", "new")).files, files);
  assert.deepEqual(pick((put, dir) => rmSync(join(dir, "gateway/test/task.test.ts"))).files, files);
});

test("mutation scope: a change to the mutation gates alone runs everything", () => {
  for (const f of ["scripts/mutation.sh", "scripts/mutation-gate.mjs", "tests/coverage/gateway-tier1.json", "tests/coverage/mutation-allowlist.json", "gateway/stryker.config.json", "gateway/vitest.mutation.config.ts", "gateway/package-lock.json", ".github/workflows/mutation.yml", ".github/workflows/ci.yml", "go.mod"]) {
    const r = pick((put) => put(f, "new"));
    assert.equal(r.scope, "all", f);
    assert.deepEqual([r.packages, r.files], [pkgs, files], f);
    assert.match(r.reason, /mutation gates/);
  }
});

test("mutation scope: fails closed to the full scope when the base cannot be used", () => {
  // No such ref.
  const r = pick((put) => put("README.md", "x"), { base: "origin/nope" });
  assert.equal(r.scope, "all");
  assert.match(r.reason, /cannot compute the changes since origin\/nope/);
  assert.deepEqual([r.packages, r.files], [pkgs, files]);

  // A shallow checkout, as actions/checkout makes by default: the PR head at depth 1 and the base fetched at depth 1
  // share no history, so there is no merge base.
  const f = fixture((put) => put("internal/binding/b.go", "new"));
  const shallow = mkdtempSync(join(tmpdir(), "parley-shallow-"));
  try {
    sh(shallow, "init", "-q", "-b", "pr");
    sh(shallow, "fetch", "-q", "--depth=1", `file://${f.dir}`, "pr");
    sh(shallow, "checkout", "-q", "FETCH_HEAD");
    sh(shallow, "fetch", "-q", "--depth=1", `file://${f.dir}`, "main:refs/remotes/origin/main");
    assert.equal(sh(shallow, "rev-parse", "--is-shallow-repository").trim(), "true");
    const s = select({ scope: "changed", base: "origin/main", pkgs, files, cwd: shallow });
    assert.equal(s.scope, "all");
    assert.match(s.reason, /cannot compute the changes/);
    assert.deepEqual([s.packages, s.files], [pkgs, files]);
  } finally {
    f.done();
    rmSync(shallow, { recursive: true, force: true });
  }
});

test("mutation scope: the full scope, and a bad scope is refused", () => {
  assert.equal(select({ scope: "all", pkgs, files }).scope, "all");
  assert.throws(() => select({ scope: "fast", pkgs, files }), /must be all or changed/);
});

test("the CI job that runs the changed-code mutation step has the full history", async () => {
  const { readFileSync } = await import("node:fs");
  const ci = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", ".github", "workflows", "ci.yml"), "utf8");
  assert.match(ci, /actions\/checkout@v4\s+with:\s+fetch-depth: 0/);
  assert.ok(!/fetch[^\n]*--depth/.test(ci), "a depth-limited fetch makes the checkout shallow again");
});
