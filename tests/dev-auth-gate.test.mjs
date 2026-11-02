// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// R9: the release gate fails when DEV_AUTH is enabled and passes when it is
// disabled or removed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { check } from "../scripts/check-dev-auth.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..");

function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), "parley-devauth-"));
  for (const [name, text] of Object.entries(files)) {
    const p = join(dir, name);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, text);
  }
  return dir;
}

test("this repository passes the gate", () => {
  assert.deepEqual(check(root), []);
  const r = spawnSync(process.execPath, [join(root, "scripts", "check-dev-auth.mjs")], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
});

test("an enabled DEV_AUTH in a release configuration fails the gate", () => {
  for (const [file, text] of [
    ["gateway/wrangler.jsonc", '{ "vars": { "DEV_AUTH": "1" } }'],
    ["gateway/wrangler.json", '{"vars":{"DEV_AUTH":"true"}}'],
    ["dashboard/wrangler.toml", '[vars]\nDEV_AUTH = "1"\n'],
    ["gateway/.dev.vars", "DEV_AUTH=1\n"],
    [".github/workflows/release.yml", "run: npx wrangler deploy --var DEV_AUTH:1\n"],
    ["gateway/wrangler.jsonc", '{ "secrets": { "required": ["DEV_AUTH"] } }'],
  ]) {
    const problems = check(repo({ [file]: text }));
    assert.equal(problems.length, 1, `${file}: ${text}`);
    assert.match(problems[0], /DEV_AUTH is enabled/);
  }
  const r = spawnSync(process.execPath, [join(root, "scripts", "check-dev-auth.mjs"), repo({ "gateway/wrangler.jsonc": '{ "vars": { "DEV_AUTH": "1" } }' })], { encoding: "utf8" });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /release gate failed/);
});

test("a disabled or removed DEV_AUTH passes", () => {
  assert.deepEqual(check(repo({ "gateway/wrangler.jsonc": '{ "vars": { "DEV_AUTH": "0" } }', "gateway/.dev.vars": "DEV_AUTH=\n" })), []);
  assert.deepEqual(check(repo({ "gateway/wrangler.jsonc": '{ "vars": { "DEV_AUTH": "false" } }' })), []);
  assert.deepEqual(check(repo({ "gateway/wrangler.jsonc": '{ "name": "gateway" }' })), []);
  assert.deepEqual(check(repo({})), []);
});

test("the development auth code path must be gone from gateway and dashboard source", () => {
  for (const [file, text] of [
    ["gateway/src/index.ts", "if (env.DEV_AUTH !== '1') return null;"],
    ["gateway/src/enroll.ts", "const m = /^Bearer dev-admin:/.exec(h);"],
    ["dashboard/worker/auth.ts", "// Bearer dev-user:t:e"],
  ]) {
    const problems = check(repo({ [file]: text }));
    assert.equal(problems.length, 1, file);
    assert.match(problems[0], /development auth path present/);
  }
});
