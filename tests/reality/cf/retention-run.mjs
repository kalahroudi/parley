// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T308 on a real Cloudflare account (run as part of reality check 2, T309): one throwaway `parley-test-*` Worker with
// one SQLite Durable Object class and one `parley-test-*` R2 bucket. Runs retention.mjs `observe`, writes the
// findings, then deletes the Worker and the bucket in a finally block and proves none remain.
//
//   PARLEY_REALITY_REAL=1 PARLEY_CF_ACCOUNT_ID=<pinned account> node tests/reality/cf/retention-run.mjs [--out file.json]
//
// Costs: a few dozen Durable Object requests and R2 operations plus one 5 MiB multipart upload that is deleted at
// once (well inside the free allowances). Nothing here prints tokens; the probe token lives in this process, the
// generated config (mode 0600, removed at the end) and the Worker's variables.
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { judge, observe } from "./retention.mjs";
import { createBucket, deleteBucket, deployRetention, destroyRetention, remaining, remainingBuckets, removeConfig, requireOptIn, verifyAccount, writeRetentionConfig } from "./safety.mjs";

const argv = process.argv.slice(2);
const out = argv.includes("--out") ? argv[argv.indexOf("--out") + 1] : null;
const log = (...a) => console.error(new Date().toISOString().slice(11, 19), ...a);

const suffix = randomBytes(3).toString("hex");
const name = `parley-test-r2-${suffix}`;
const bucket = `parley-test-r2-${suffix}`;
const token = randomBytes(24).toString("hex");
const result = { name, bucket, startedAt: new Date().toISOString() };

let failure;
let call;
const created = { bucket: false, worker: false };
try {
  requireOptIn();
  verifyAccount();
  log(`account verified; creating bucket ${bucket}`);
  // The config file (account pinned, workers.dev only) is needed by the bucket commands too.
  writeRetentionConfig(name, bucket, {});
  createBucket(name, bucket);
  created.bucket = true;
  const origin = deployRetention(name, bucket, { PROBE_TOKEN: token });
  created.worker = true;
  for (const t0 = Date.now(); ; ) {
    const r = await fetch(`${origin}/healthz`);
    if (r.ok) break;
    if (Date.now() - t0 > 90_000) throw new Error(`healthz ${r.status} after 90 s`);
    await new Promise((r) => setTimeout(r, 3000));
  }
  call = async (path, body) => {
    const r = await fetch(`${origin}${path}`, { method: "POST", headers: { "x-probe-token": token, "content-type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(`${path} ${r.status}: ${j.error ?? ""}`);
    return j.result;
  };
  log("observing");
  const obs = await observe(call, { real: true });
  result.observations = obs;
  result.verdict = judge(obs);
  const leftovers = (await call("/__r2", { op: "list", prefix: "" })).keys;
  if (leftovers.length) throw new Error(`the bucket still holds ${leftovers.length} object(s); cannot delete it`);
} catch (err) {
  failure = err;
  log(`FAILED: ${err.message}`);
} finally {
  log("cleanup");
  const step = async (what, fn) => {
    try {
      await fn();
    } catch (err) {
      log(`${what} failed: ${err.message}`);
      failure ??= err;
    }
  };
  // A run that failed midway can leave objects behind, and R2 refuses to delete a bucket that is not empty: empty it
  // through the Worker while the Worker still exists.
  if (created.worker && call) {
    await step("empty bucket", async () => {
      const keys = (await call("/__r2", { op: "list", prefix: "" })).keys;
      for (let i = 0; i < keys.length; i += 100) await call("/__r2", { op: "delete", keys: keys.slice(i, i + 100) });
    });
  }
  if (created.worker) await step("worker delete", () => destroyRetention(name, bucket));
  if (created.bucket) await step("bucket delete", () => deleteBucket(name, bucket));
  await step("verify", () => {
    result.remainingWorkers = remaining();
    result.remainingBuckets = remainingBuckets(name);
    if (result.remainingWorkers.length || result.remainingBuckets.length) throw new Error(`parley-test-* resources remain: ${JSON.stringify([result.remainingWorkers, result.remainingBuckets])}`);
  });
  removeConfig(name);
  result.finishedAt = new Date().toISOString();
  result.failure = failure ? failure.message : null;
  const file = out ?? join(tmpdir(), `${name}-results.json`);
  writeFileSync(file, JSON.stringify(result, null, 2));
  log(`results in ${file}`);
  process.exitCode = failure ? 1 : 0;
}
