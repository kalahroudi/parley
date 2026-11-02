// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109 (reality check 1): probes a gateway deployed to a real Cloudflare account.
// See specs/parley-mvp/reality-check-1.md for the full procedure.
//
//   node tests/reality/probe.mjs limits       --url https://<worker>.workers.dev
//   node tests/reality/probe.mjs hibernation  --url ... [--idle 10,60,300,1800] [--heartbeat]
//   node tests/reality/probe.mjs deploy       --url ... [--minutes 5]     (run `wrangler deploy` meanwhile)
//   node tests/reality/probe.mjs logins       --url ... (needs the IdP ids in the environment)
//   node tests/reality/probe.mjs cost         --usage usage.json [--messages-per-day N --awake-seconds-per-day N]
//   node tests/reality/probe.mjs report       [--out file.md]
//
// Each command merges its result into tests/reality/results.json (git-ignored).
// The probes authenticate with the development bearer token, so deploy the
// throwaway worker with DEV_AUTH=1 only for the check and delete it afterwards.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkLoginRedirect, estimateCost, perDeviceMonth, probeDeploy, probeFrameLimits, probeHibernation, renderReport } from "./lib.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const RESULTS = join(here, "results.json");
const load = () => (existsSync(RESULTS) ? JSON.parse(readFileSync(RESULTS, "utf8")) : {});
const save = (patch) => writeFileSync(RESULTS, JSON.stringify({ ...load(), ...patch }, null, 2) + "\n");

function args(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) out._.push(a);
    else if (argv[i + 1] === undefined || argv[i + 1].startsWith("--")) out[a.slice(2)] = true;
    else out[a.slice(2)] = argv[++i];
  }
  return out;
}

// Node's built-in WebSocket (undici) accepts a headers option; it is the only
// way to send the bearer token, because identifiers never go in URLs.
function tunnelOpts(a) {
  if (!a.url) throw new Error("--url is required");
  const url = new URL("/v1/connect", a.url);
  url.protocol = url.protocol === "http:" ? "ws:" : "wss:";
  const tenant = a.tenant ?? "reality";
  return { WebSocket, url: url.toString(), token: `dev:${tenant}:${a.device ?? "probe"}` };
}

const commands = {
  async limits(a) {
    const limits = await probeFrameLimits(tunnelOpts(a));
    save({ limits, when: new Date().toISOString(), gateway: new URL(a.url).host });
    return limits;
  },
  async hibernation(a) {
    const idle = String(a.idle ?? "10,60,300,1800").split(",").map(Number);
    const h = await probeHibernation(tunnelOpts(a), idle, { heartbeat: !!a.heartbeat });
    save({ hibernation: [...(load().hibernation ?? []).filter((x) => x.heartbeat !== h.heartbeat), h] });
    return h;
  },
  async deploy(a) {
    console.error("probing; run `wrangler deploy` (twice, a minute apart, with a code change) now");
    const d = await probeDeploy(tunnelOpts(a), {
      durationMs: Number(a.minutes ?? 5) * 60_000,
      onEvent: (e) => console.error(JSON.stringify(e)),
    });
    save({ deploy: d });
    return d;
  },
  async logins(a) {
    if (!a.url) throw new Error("--url is required");
    const origin = new URL(a.url).origin;
    const cfg = {
      google: { clientId: process.env.GOOGLE_CLIENT_ID },
      entra: { clientId: process.env.ENTRA_CLIENT_ID, tenantId: process.env.ENTRA_TENANT_ID },
    };
    const rows = [];
    for (const [provider, c] of Object.entries(cfg)) {
      if (!c.clientId) {
        rows.push({ provider, redirect: "NOT RUN (no client id in env)" });
        continue;
      }
      const res = await fetch(`${origin}/auth/${provider}/login`, { redirect: "manual" });
      const loc = res.headers.get("location");
      const r = res.status === 302 && loc ? checkLoginRedirect(provider, loc, { ...c, gatewayOrigin: origin }) : { ok: false, problems: [`status ${res.status}`] };
      rows.push({ provider, redirect: r.ok ? "ok" : `FAIL: ${r.problems.join("; ")}`, loginUrl: `${origin}/auth/${provider}/login` });
      console.error(`${provider}: open ${origin}/auth/${provider}/login in a browser, sign in, then record the result in the report`);
    }
    // Keep hand-recorded fields from an earlier run.
    const prev = load().logins ?? [];
    save({ logins: rows.map((x) => ({ ...(prev.find((p) => p.provider === x.provider) ?? {}), ...x })) });
    return rows;
  },
  async cost(a) {
    const pricing = JSON.parse(readFileSync(join(here, "pricing.json"), "utf8"));
    if (pricing.pricingAsOf === "NOT SET") throw new Error("set pricingSource and pricingAsOf in pricing.json from Cloudflare's current price pages first");
    const usage = JSON.parse(readFileSync(a.usage, "utf8"));
    const cost = { pricingSource: pricing.pricingSource, pricingAsOf: pricing.pricingAsOf, usage, estimate: estimateCost(usage, pricing) };
    if (a["messages-per-day"]) cost.perDevice = perDeviceMonth({ messagesPerDay: Number(a["messages-per-day"]), awakeSecondsPerDay: Number(a["awake-seconds-per-day"] ?? 0) }, pricing);
    save({ cost });
    return cost;
  },
  async report(a) {
    const md = renderReport(load());
    if (a.out) writeFileSync(a.out, md);
    return md;
  },
};

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const a = args(process.argv.slice(2));
  const cmd = commands[a._[0]];
  if (!cmd) {
    console.error(`usage: probe.mjs ${Object.keys(commands).join("|")} [options]`);
    process.exit(2);
  }
  try {
    const out = await cmd(a);
    console.log(typeof out === "string" ? out : JSON.stringify(out, null, 2));
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
