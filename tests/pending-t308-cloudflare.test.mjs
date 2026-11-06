// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T308's measurement on real Cloudflare (tests/reality/cf/retention-run.mjs) belongs to reality check 2 (T309) and
// needs the account owner's go-ahead. Until its result is committed as specs/parley-mvp/retention-reality-data.json
// this is a named pending test: while T309 is open it passes only by asserting that state (no result, T309 unticked)
// and recording the reason; it FAILS once T309 is ticked. Once the file exists it checks the file, so a stale or
// partial result cannot stand in for the run. Nothing in this file is skipped.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { taskTicked } from "./harness/pending.mjs";
import { judge, observe } from "./reality/cf/retention.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const data = join(root, "specs", "parley-mvp", "retention-reality-data.json");
const reason = "run `node tests/reality/cf/retention-run.mjs --out specs/parley-mvp/retention-reality-data.json` on the pinned account (see specs/parley-mvp/retention-reality.md)";

function validate(raw) {
  const r = JSON.parse(raw);
  assert.equal(r.failure, null, "the run failed");
  assert.deepEqual([r.remainingWorkers, r.remainingBuckets], [[], []], "parley-test-* resources were left behind");
  assert.equal(r.observations.real, true, "the result is not from Cloudflare");
  assert.deepEqual(r.verdict, judge(r.observations), "the stored verdict does not follow from the observations");
  for (const f of r.verdict.findings) {
    if (f.id === "r2-physical") assert.equal(f.status, "not measured");
    else assert.ok(["confirmed", "refuted"].includes(f.status), `${f.id} is ${f.status}: ${f.detail}`);
  }
  // Nothing but booleans, sizes, timings and error text is stored.
  assert.doesNotMatch(raw, /\b[0-9a-f]{32}\b/, "an identifier or secret-shaped value is in the result");
}

test("pending T309: recovery-bookmark and R2 deletion results measured on Cloudflare", (t) => {
  if (!existsSync(data)) {
    assert.equal(taskTicked(readFileSync(join(root, "specs", "parley-mvp", "tasks.md"), "utf8"), "T309"), false, `T309 is ticked but the Cloudflare retention result is missing: ${reason}`);
    return t.diagnostic(`pending T309: ${reason}`);
  }
  validate(readFileSync(data, "utf8"));
});

test("the result check accepts a complete Cloudflare run and rejects every way a result can be a stand-in", async () => {
  // A store that keeps history, so the run is complete and every finding is confirmed or refuted.
  const state = { kv: {}, sql: {} };
  const marks = new Map();
  const objects = new Map();
  const call = async (path, b) => {
    if (path === "/__r2") {
      if (b.op === "put") return objects.set(b.key, b.body), { size: 1 };
      if (b.op === "head") return objects.has(b.key) ? { size: 1 } : null;
      if (b.op === "get") return objects.has(b.key) ? { body: "" } : null;
      if (b.op === "list") return { keys: [...objects.keys()].filter((k) => k.startsWith(b.prefix)) };
      if (b.op === "delete") return (b.keys ?? [b.key]).forEach((k) => objects.delete(k)), {};
      return { size: 5 * 1024 * 1024 + 4 };
    }
    const [a, c, d] = b.args;
    switch (b.op) {
      case "put": state.kv[a] = c; return null;
      case "putSql": state.sql[a] = c; return null;
      case "del": delete state.kv[a]; delete state.sql[a]; return null;
      case "holdWithTtl": state.kv[a] = c; setTimeout(() => delete state.kv[a], d); return null;
      case "wipe": state.kv = {}; state.sql = {}; return null;
      case "read": return structuredClone(state);
      case "bookmark": marks.set(`b${marks.size}`, structuredClone(state)); return `b${marks.size - 1}`;
      case "bookmarkAt": if (a < Date.now() - 30 * 864e5) throw new Error("outside the window"); return "t";
      case "restore": Object.assign(state, structuredClone(marks.get(a))); return "reset";
    }
  };
  const observations = await observe(call, { real: true, ttlMs: 10, settleMs: 40 });
  const good = { failure: null, remainingWorkers: [], remainingBuckets: [], observations, verdict: judge(observations) };
  validate(JSON.stringify(good));
  const bad = (change, re) => assert.throws(() => validate(JSON.stringify({ ...good, ...change })), re);
  bad({ failure: "boom" }, /the run failed/);
  bad({ remainingBuckets: ["parley-test-r2-x"] }, /left behind/);
  bad({ remainingWorkers: ["parley-test-r2-x"] }, /left behind/);
  bad({ observations: { ...observations, real: false }, verdict: judge({ ...observations, real: false }) }, /not from Cloudflare/);
  bad({ verdict: { ...good.verdict, findings: good.verdict.findings.map((f) => ({ ...f, status: "confirmed" })) } }, /does not follow/);
  const local = { ...observations, do: { ...observations.do, placeholderBookmarks: true } };
  bad({ observations: local, verdict: judge(local) }, /not measured/);
  assert.throws(() => validate(JSON.stringify({ ...good, note: "0123456789abcdef0123456789abcdef" })), /secret-shaped/);
});
