// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109 (reality check 1, Cloudflare half). Deploys ONE throwaway `parley-test-*`
// Worker to the pinned account, runs the experiments, and deletes it again in a
// finally block, then proves no `parley-test-*` Worker remains. See
// specs/parley-mvp/reality-check-1.md for the plan and the measured results.
//
//   node tests/reality/cf/run.mjs [--only limits,hibernation,deploy,soak] [--idle-long 600] [--out file.json]
//
// Nothing here prints tokens; the probe token lives in this process, the
// generated config (mode 0600, removed at the end) and the child's environment.
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as ex from "./experiments.mjs";
import { ACCOUNT_ID, deploy, deployAsync, destroy, remaining, removeConfig, verifyAccount } from "./safety.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..", "..");
const argv = process.argv.slice(2);
const args = {};
for (let i = 0; i < argv.length; i++) if (argv[i].startsWith("--")) args[argv[i].slice(2)] = argv[i + 1]?.startsWith("--") || argv[i + 1] === undefined ? true : argv[++i];
const only = new Set(String(args.only ?? "limits,hibernation,deploy,soak").split(","));
const idleLong = Number(args["idle-long"] ?? 600);
const log = (...a) => console.error(new Date().toISOString().slice(11, 19), ...a);

const name = `parley-test-r1-${randomBytes(3).toString("hex")}`;
const tenant = `r1${randomBytes(6).toString("hex")}`;
const probeToken = randomBytes(24).toString("hex");
const vars = (build) => ({ DEV_AUTH: "1", PROBE_TOKEN: probeToken, BUILD: build });
const stats = { wsMessages: 0, connections: 0, deploys: 0, httpRequests: 0 };
const results = { name, startedAt: new Date().toISOString(), plan: {}, experiments: {}, stats, versions: {} };

async function main() {
  verifyAccount();
  log(`account ${ACCOUNT_ID.slice(0, 8)}... verified; deploying ${name}`);
  const t0 = Date.now();
  const origin = deploy(name, vars("build-0"));
  stats.deploys++;
  results.initialDeployMs = Date.now() - t0;
  const wsUrl = origin.replace("https:", "wss:") + "/v1/connect";
  const health = await fetch(`${origin}/healthz`);
  stats.httpRequests++;
  if (!health.ok) throw new Error(`healthz ${health.status}`);
  const ctx = { WebSocket, url: wsUrl, token: (d) => `dev:${tenant}:${d}`, stats };
  const step = async (key, fn) => {
    if (!only.has(key)) return;
    log(`experiment: ${key}`);
    results.experiments[key] = await fn();
  };

  await step("limits", () => ex.limits(ctx));

  await step("hibernation", async () => {
    const [ladder, pings, quiet, hb] = await Promise.all([
      ex.ladder(ctx, [2, 5, 8, 10, 12, 15, 20, 30]),
      ex.pings(ctx),
      ex.longIdle(ctx, idleLong, false),
      ex.longIdle(ctx, idleLong, true),
    ]);
    return { ladder, pings, longIdle: { quiet, heartbeat: hb } };
  });

  let build = 0;
  const deployOnce = async () => {
    build++;
    await deployAsync(name, vars(`build-d${build}`));
    stats.deploys++;
  };
  await step("deploy", () => ex.deployDuringSockets(ctx, deployOnce));

  await step("soak", async () => {
    const outFile = join(process.env.TMPDIR ?? "/tmp", `${name}-soak.json`);
    const deployScript = join(here, "deploy.mjs");
    const r = spawnSync("go", ["test", "-count=1", "-run", "TestRealSoak", "-timeout", "30m", "./internal/tunnel"], {
      cwd: repo,
      encoding: "utf8",
      env: {
        ...process.env,
        PARLEY_REALITY_URL: wsUrl,
        PARLEY_REALITY_TENANT: tenant,
        PARLEY_REALITY_PROBE_TOKEN: probeToken,
        PARLEY_REALITY_DEPLOY_CMD: JSON.stringify([process.execPath, deployScript]),
        PARLEY_REALITY_NAME: name,
        PARLEY_REALITY_OUT: outFile,
        PARLEY_REALITY_FORCED: "20",
        PARLEY_REALITY_DEPLOYS: "3",
        PARLEY_REALITY_TOTAL: "10000",
      },
    });
    const tail = (s) => s.split("\n").filter((l) => !l.includes(probeToken)).slice(-15).join("\n");
    let detail = null;
    try {
      detail = JSON.parse((await import("node:fs")).readFileSync(outFile, "utf8"));
    } catch {}
    return { passed: r.status === 0, goOutput: tail(r.stdout + r.stderr), detail };
  });
}

let failure;
try {
  await main();
} catch (err) {
  failure = err;
  log(`FAILED: ${err.message}`);
} finally {
  log(`cleanup: deleting ${name}`);
  try {
    destroy(name);
  } catch (err) {
    log(`delete failed: ${err.message}`);
    failure ??= err;
  }
  removeConfig(name);
  try {
    results.remainingAfterCleanup = remaining();
  } catch (err) {
    results.remainingAfterCleanup = `unknown: ${err.message}`;
    failure ??= err;
  }
  results.finishedAt = new Date().toISOString();
  results.failure = failure ? failure.message : null;
  const out = typeof args.out === "string" ? args.out : join(process.env.TMPDIR ?? "/tmp", `${name}-results.json`);
  writeFileSync(out, JSON.stringify(results, null, 2));
  log(`results in ${out}; remaining parley-test-* workers: ${JSON.stringify(results.remainingAfterCleanup)}`);
  process.exit(failure ? 1 : 0);
}
