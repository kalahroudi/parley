// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109: the safety rails around anything that touches a real Cloudflare account.
import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { existsSync, readFileSync, statSync } from "node:fs";
import { ACCOUNT_ID, assertName, configPath, remaining, removeConfig, secretCommand, secretNames, verifyAccount, wranglerConfig, writeConfig } from "./safety.mjs";

test("only parley-test-* worker names are accepted", () => {
  assert.equal(assertName("parley-test-r1-abc123"), "parley-test-r1-abc123");
  for (const bad of ["bulkhead-demo", "parley-test", "parley-testing-x", "Parley-test-x", "parley-test-x/../y", "parley-test-", "", "parley-test-x y", `parley-test-${"a".repeat(60)}`]) {
    assert.throws(() => assertName(bad), /refusing Worker name/, bad);
  }
});

test("the account is verified with `cf accounts list` and a missing target aborts", () => {
  const calls = [];
  const run = (ids) => (cmd, args) => (calls.push([cmd, ...args]), JSON.stringify(ids.map((id) => ({ id }))));
  assert.equal(verifyAccount(run([ACCOUNT_ID, "e2bc588eb3e8cc1eb913146950f30889"])), true);
  assert.deepEqual(calls, [["cf", "accounts", "list"]]);
  assert.throws(() => verifyAccount(run(["e2bc588eb3e8cc1eb913146950f30889"])), /b891d462\.\.\. not found/);
  assert.throws(() => verifyAccount(() => "not json"), /cannot verify/);
  assert.throws(() => verifyAccount(() => { throw new Error("cf missing"); }), /cannot verify.*cf missing/);
});

test("the generated config pins the account and only enables workers.dev", () => {
  const c = wranglerConfig({ name: "parley-test-r1-x", entry: "/e.ts", vars: { A: "1" } });
  assert.equal(c.account_id, ACCOUNT_ID);
  assert.equal(c.workers_dev, true);
  assert.equal(c.preview_urls, false);
  assert.equal(c.observability.enabled, false);
  for (const k of ["routes", "route", "zone_id", "d1_databases", "kv_namespaces", "r2_buckets"]) assert.ok(!(k in c), k);
  assert.deepEqual(c.durable_objects.bindings.map((b) => b.class_name), ["Device", "Tenant"]);
  assert.throws(() => wranglerConfig({ name: "other", entry: "/e.ts", vars: {} }), /refusing/);
});

test("the config is written privately outside the repo and removed afterwards", () => {
  const path = writeConfig("parley-test-r1-unit", { PROBE_TOKEN: "t" });
  try {
    assert.ok(path.startsWith(tmpdir()), "outside the repo tree");
    assert.equal(statSync(path).mode & 0o077, 0, "owner-only");
    assert.equal(JSON.parse(readFileSync(path, "utf8")).vars.PROBE_TOKEN, "t");
  } finally {
    removeConfig("parley-test-r1-unit");
  }
  assert.ok(!existsSync(path));
});

test("remaining lists only parley-test-* names after verifying the account", () => {
  const seen = [];
  const r = remaining((cmd, args) => (seen.push(args.join(" ")), args[0] === "accounts" ? JSON.stringify([{ id: ACCOUNT_ID }]) : '[{"id":"parley-test-r1-aa"},{"id":"parley-test-r1-aa"},{"id":"bulkhead-demo"}]'));
  assert.deepEqual(r, ["parley-test-r1-aa"]);
  assert.ok(seen.length >= 1);
});

test("secretCommand is the wrangler prompt against the pinned config, and refuses odd names", () => {
  const cmd = secretCommand("parley-test-login", "GOOGLE_CLIENT_SECRET");
  assert.equal(cmd, `cd gateway && npx wrangler secret put GOOGLE_CLIENT_SECRET --name parley-test-login --config ${JSON.stringify(configPath("parley-test-login"))}`);
  assert.doesNotMatch(cmd, /=|echo|<</, "no value can be on the command line");
  assert.throws(() => secretCommand("other-worker", "X"), /refusing/);
  assert.throws(() => secretCommand("parley-test-login", "x; rm -rf /"), /bad secret name/);
});

test("secretNames returns names only, checks the account first, and is [] when the Worker does not exist", () => {
  const seen = [];
  const verify = () => seen.push("verify");
  const run = (args, config) => (seen.push(args.join(" ")), '[{"name":"A","type":"secret_text"},{"name":"B","type":"secret_text"}]');
  assert.deepEqual(secretNames("parley-test-login", run, verify), ["A", "B"]);
  assert.deepEqual(seen, ["verify", "secret list --format json"]);
  assert.deepEqual(secretNames("parley-test-login", () => { throw new Error("no such worker"); }, verify), []);
  assert.deepEqual(secretNames("parley-test-login", () => "not json", verify), []);
  assert.throws(() => secretNames("other", run, verify), /refusing/);
  assert.throws(() => secretNames("parley-test-login", run, () => { throw new Error("wrong account"); }), /wrong account/);
});
