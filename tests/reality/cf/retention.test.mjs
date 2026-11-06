// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T308: the measurement and its verdicts. The real Cloudflare run is retention-run.mjs (reality check 2); here the
// logic is tested against a model of a retaining object store, a non-retaining one, and the local runtime.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { freePorts, sleep, stopTree } from "../../harness/wrangler.mjs";
import { PLACEHOLDER_BOOKMARK, judge, observe } from "./retention.mjs";
import { retentionEntryPath } from "./safety.mjs";

const gatewayDir = join(fileURLToPath(import.meta.url), "..", "..", "..", "..", "gateway");
const wrangler = join(gatewayDir, "node_modules", ".bin", process.platform === "win32" ? "wrangler.cmd" : "wrangler");

// A model of the measurement Worker. `history`: deleted rows can be restored from a bookmark (Cloudflare's behavior).
// `placeholder`: the local runtime's all-zero bookmark, which restores nothing. `window`: refuses times > 30 days back.
function model({ history, placeholder = false, r2Lag = false }) {
  const objects = new Map();
  const state = { kv: {}, sql: {} };
  const marks = new Map();
  let n = 0;
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const dos = async (op, args) => {
    switch (op) {
      case "put": state.kv[args[0]] = args[1]; return null;
      case "putSql": state.sql[args[0]] = args[1]; return null;
      case "del": delete state.kv[args[0]]; delete state.sql[args[0]]; return null;
      case "holdWithTtl": state.kv[args[0]] = args[1]; setTimeout(() => delete state.kv[args[0]], args[2]); return null;
      case "wipe": state.kv = {}; state.sql = {}; return null;
      case "read": return clone(state);
      case "bookmark": {
        if (placeholder) return "00000000-00000000-00000000-00000000000000000000000000000000";
        const id = `bm-${++n}`;
        marks.set(id, clone(state));
        return id;
      }
      case "bookmarkAt":
        if (args[0] < Date.now() - 30 * 24 * 3600 * 1000) throw new Error("bookmark time is outside the recovery window");
        return "bm-time";
      case "restore": {
        if (history && !placeholder) Object.assign(state, clone(marks.get(args[0])));
        return "reset";
      }
    }
  };
  const r2 = async (b) => {
    switch (b.op) {
      case "put": objects.set(b.key, b.body); return { size: b.body.length };
      case "head": return objects.has(b.key) ? { size: objects.get(b.key).length } : null;
      case "get": return objects.has(b.key) ? { body: objects.get(b.key) } : null;
      case "list": return { keys: [...objects.keys()].filter((k) => k.startsWith(b.prefix ?? "")) };
      case "delete": for (const k of b.keys ?? [b.key]) if (!r2Lag) objects.delete(k); return { deleted: 1 };
      case "multipart": objects.set(b.key, "x".repeat(5 * 1024 * 1024 + 4)); return { size: 5 * 1024 * 1024 + 4 };
      case "multipart-abort": return { aborted: true };
    }
  };
  return (path, body) => (path === "/__vault" ? dos(body.op, body.args) : r2(body));
}
const fast = { ttlMs: 20, settleMs: 60 };
const byId = (v) => Object.fromEntries(v.findings.map((f) => [f.id, f.status]));

test("a store that keeps history: deleted rows come back, and the claim is confirmed", async () => {
  const obs = await observe(model({ history: true }), { real: true, ...fast });
  assert.equal(obs.do.deletedFromObject, true);
  assert.deepEqual([obs.do.restoredKv, obs.do.restoredSql, obs.do.alarmDeleted, obs.do.restoredAfterAlarm, obs.do.wipedEmpty, obs.do.restoredAfterWipe], [true, true, true, true, true, true]);
  const v = judge(obs);
  assert.equal(v.real, true);
  assert.deepEqual(byId(v), { "do-restore-delete": "confirmed", "do-restore-alarm": "confirmed", "do-restore-wipe": "confirmed", "do-window": "confirmed", "r2-delete": "confirmed", "r2-delete-idempotent": "confirmed", "r2-multipart": "confirmed", "r2-physical": "not measured" });
});

test("a store that keeps no history refutes the recovery findings, and says the delete did happen", async () => {
  const v = judge(await observe(model({ history: false }), { real: true, ...fast }));
  assert.deepEqual([byId(v)["do-restore-delete"], byId(v)["do-restore-alarm"], byId(v)["do-restore-wipe"]], ["refuted", "refuted", "refuted"]);
  assert.match(v.findings[0].detail, /not readable after the restore/);
});

test("a placeholder bookmark (the local runtime) is reported as not measured, never as a pass", async () => {
  const obs = await observe(model({ history: false, placeholder: true }), { real: false, ...fast });
  assert.equal(obs.do.placeholderBookmarks, true);
  const v = judge(obs);
  assert.equal(v.real, false);
  assert.deepEqual([byId(v)["do-restore-delete"], byId(v)["do-restore-alarm"], byId(v)["do-restore-wipe"], byId(v)["do-window"]], ["not measured", "not measured", "not measured", "not measured"]);
  assert.match(v.findings[0].detail, /local runtime only/);
  assert.ok(PLACEHOLDER_BOOKMARK.test("00000000-00000000-00000000-00000000000000000000000000000000"));
  assert.ok(!PLACEHOLDER_BOOKMARK.test("0000000a-00000000-00000000-0000000000000000000000000000000f"));
});

test("an R2 delete that is not immediately visible is refuted", async () => {
  const v = judge(await observe(model({ history: true, r2Lag: true }), { real: true, ...fast }));
  assert.equal(byId(v)["r2-delete"], "refuted");
});

test("a delete that did not take effect cannot be read as a recovery, and a window that never ends is refuted", async () => {
  const obs = await observe(model({ history: true }), { real: true, ...fast });
  const stuck = judge({ ...obs, do: { ...obs.do, deletedFromObject: false, alarmDeleted: false, wipedEmpty: false, bookmark31Days: { ok: true } } });
  assert.deepEqual([byId(stuck)["do-restore-delete"], byId(stuck)["do-restore-alarm"], byId(stuck)["do-restore-wipe"], byId(stuck)["do-window"]], ["incomplete", "incomplete", "incomplete", "refuted"]);
  assert.match(stuck.findings[0].detail, /did not take effect/);
  const noRecent = judge({ ...obs, do: { ...obs.do, bookmarkRecent: { ok: false, error: "x" } } });
  assert.equal(byId(noRecent)["do-window"], "refuted");
});

test("a run missing any observation is incomplete, not a pass", async () => {
  const obs = await observe(model({ history: true }), { real: true, ...fast });
  for (const [group, key] of [["do", "restoredSql"], ["r2", "batchDeleted"]]) {
    const copy = { ...obs, [group]: { ...obs[group] } };
    delete copy[group][key];
    const v = judge(copy);
    assert.deepEqual(v.findings.map((f) => f.status), ["incomplete"]);
    assert.match(v.findings[0].detail, new RegExp(`${group}\\.${key}`));
  }
});

test("observe returns booleans, sizes and timings only: nothing it wrote", async () => {
  const written = [];
  const base = model({ history: true });
  const spy = (path, body) => (written.push(JSON.stringify(body)), base(path, body));
  const obs = await observe(spy, { real: true, ...fast });
  const out = JSON.stringify(obs);
  const values = written.flatMap((w) => w.match(/[0-9a-f]{24}/g) ?? []);
  assert.ok(values.length >= 5, "the run wrote random values");
  for (const v of values) assert.ok(!out.includes(v), "a written value appears in the observations");
});

// The local runtime as a stand-in: wrangler dev with the real measurement Worker. R2 behavior is real miniflare R2;
// the bookmark API is a placeholder, so the Durable Object findings must come out "not measured".
const missing = !existsSync(wrangler) ? "gateway dependencies not installed (cd gateway && npm ci)" : "";
test("the measurement Worker under wrangler dev: R2 findings hold, Durable Object findings are not measured", { ...(missing && !process.env.CI ? { skip: missing } : {}), timeout: 180_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "parley-t308-"));
  const token = "local-probe-token";
  const config = join(dir, "wrangler.jsonc");
  writeFileSync(config, JSON.stringify({ name: "parley-test-local", main: retentionEntryPath, compatibility_date: "2026-10-01", durable_objects: { bindings: [{ name: "VAULT", class_name: "Vault" }] }, migrations: [{ tag: "v1", new_sqlite_classes: ["Vault"] }], r2_buckets: [{ binding: "BUCKET", bucket_name: "parley-test-local" }], vars: { PROBE_TOKEN: token } }));
  const [port, inspector] = await freePorts(2);
  const chunks = [];
  const child = spawn(`"${wrangler}" dev --config "${config}" --port ${port} --inspector-port ${inspector} --ip 127.0.0.1 --persist-to "${join(dir, "state")}"`, {
    cwd: gatewayDir,
    shell: true,
    detached: process.platform !== "win32",
    env: { ...process.env, WRANGLER_LOG_PATH: join(dir, "logs"), WRANGLER_REGISTRY_PATH: join(dir, "registry"), WRANGLER_SEND_METRICS: "false", CI: "1" },
  });
  child.stdout.on("data", (d) => chunks.push(d));
  child.stderr.on("data", (d) => chunks.push(d));
  try {
    const url = `http://127.0.0.1:${port}`;
    for (let up = false, t0 = Date.now(); !up; await sleep(200)) {
      if (child.exitCode !== null || Date.now() - t0 > 90_000) throw new Error(`wrangler dev did not start:\n${Buffer.concat(chunks)}`);
      up = await fetch(`${url}/healthz`).then((r) => r.ok, () => false);
    }
    const call = async (path, body) => {
      const r = await fetch(`${url}${path}`, { method: "POST", headers: { "x-probe-token": token, "content-type": "application/json" }, body: JSON.stringify(body) });
      const j = await r.json();
      assert.ok(r.ok, `${path} ${r.status} ${JSON.stringify(j)}`);
      return j.result;
    };
    assert.equal((await fetch(`${url}/__r2`, { method: "POST", body: "{}" })).status, 401, "the probe endpoints need the token");
    const obs = await observe(call, { real: false, ...fast });
    assert.equal(obs.do.placeholderBookmarks, true, "the local runtime now returns real bookmarks: measure them here too");
    const v = judge(obs);
    assert.equal(v.real, false);
    assert.deepEqual(byId(v), { "do-restore-delete": "not measured", "do-restore-alarm": "not measured", "do-restore-wipe": "not measured", "do-window": "not measured", "r2-delete": "confirmed", "r2-delete-idempotent": "confirmed", "r2-multipart": "confirmed", "r2-physical": "not measured" });
  } finally {
    await stopTree(child);
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
});

test("retention-run.mjs refuses to touch Cloudflare without the opt-in, and cleans up after itself", () => {
  const env = { ...process.env, PARLEY_REALITY_REAL: "", PARLEY_CF_ACCOUNT_ID: "" };
  const out = join(mkdtempSync(join(tmpdir(), "parley-t308-run-")), "result.json");
  try {
    const r = spawnSync(process.execPath, [join(fileURLToPath(import.meta.url), "..", "retention-run.mjs"), "--out", out], { env, encoding: "utf8" });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /refusing to touch a real Cloudflare account/);
    assert.doesNotMatch(r.stderr, /creating bucket|deploy/);
    const result = JSON.parse(readFileSync(out, "utf8"));
    assert.match(result.failure, /set PARLEY_REALITY_REAL=1/);
    assert.equal(result.observations, undefined, "nothing was observed");
  } finally {
    rmSync(join(out, ".."), { recursive: true, force: true });
  }
});
