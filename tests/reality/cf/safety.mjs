// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109 safety rails for anything that touches a real Cloudflare account. Every
// Cloudflare call in run.mjs goes through here: the account is pinned and checked
// first, and only Workers named `parley-test-*` can be deployed or deleted.
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const PREFIX = "parley-test-";
const NAME = /^parley-test-[a-z0-9][a-z0-9-]{0,40}$/;
const here = fileURLToPath(new URL(".", import.meta.url));
const gatewayDir = resolve(here, "..", "..", "..", "gateway");

// Nothing here runs against a real account by accident: a person opts in for the shell session that
// runs it, and names the account. The account id is never in the repo, a log or a report.
export const OPT_IN = "PARLEY_REALITY_REAL";
export const ACCOUNT_ENV = "PARLEY_CF_ACCOUNT_ID";

export function requireOptIn(env = process.env) {
  if (env[OPT_IN] !== "1") throw new Error(`refusing to touch a real Cloudflare account: set ${OPT_IN}=1 to opt in (see specs/parley-mvp/reality-check-1.md)`);
}

export function accountId(env = process.env) {
  const id = env[ACCOUNT_ENV];
  if (!/^[0-9a-f]{32}$/.test(id ?? "")) throw new Error(`${ACCOUNT_ENV} must be the 32-character hex id of the account to use (the login has more than one account; the default never decides)`);
  return id;
}

// Hard ceilings on what one run may spend, counted by the run itself, so a loop that goes wrong stops
// instead of billing. They sit far above what the measured plan uses (see reality-check-1.md).
export const CEILING = { wsMessages: 2_000_000, connections: 20_000, httpRequests: 5_000, deploys: 12 };
export function checkCeiling(stats, ceiling = CEILING) {
  for (const [k, max] of Object.entries(ceiling)) if ((stats[k] ?? 0) > max) throw new Error(`spend ceiling reached: ${k} ${stats[k]} > ${max}; stopping and cleaning up`);
}

export function assertName(name) {
  if (!NAME.test(name)) throw new Error(`refusing Worker name ${JSON.stringify(name)}: must match ${NAME}`);
  return name;
}

// `cf accounts list` must show the target account; the login has two accounts and
// the default must never decide. Aborts otherwise.
export function verifyAccount(run = (cmd, args) => execFileSync(cmd, args, { encoding: "utf8" }), env = process.env) {
  requireOptIn(env);
  const want = accountId(env);
  let ids;
  try {
    ids = JSON.parse(run("cf", ["accounts", "list"])).map((a) => a.id);
  } catch (err) {
    throw new Error(`cannot verify the Cloudflare account: ${err.message}`);
  }
  if (!ids.includes(want)) throw new Error(`the account named by ${ACCOUNT_ENV} is not in \`cf accounts list\`; aborting`);
  return true;
}

// A generated wrangler config outside the repo tree. The account is pinned, only
// workers.dev is enabled (no routes, domains or previews), and logging is off.
export function wranglerConfig({ name, entry, vars }, env = process.env) {
  assertName(name);
  return {
    name,
    account_id: accountId(env),
    main: entry,
    compatibility_date: "2026-10-01",
    workers_dev: true,
    preview_urls: false,
    observability: { enabled: false },
    vars,
    durable_objects: { bindings: [{ name: "DEVICE", class_name: "Device" }, { name: "TENANT", class_name: "Tenant" }] },
    migrations: [
      { tag: "v1", new_sqlite_classes: ["Device"] },
      { tag: "v2", new_sqlite_classes: ["Tenant"] },
    ],
  };
}

export const entryPath = resolve(here, "worker", "entry.ts");

export function workDir(name) {
  const dir = join(tmpdir(), assertName(name));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

export function writeConfig(name, vars) {
  requireOptIn();
  const dir = workDir(name);
  const path = join(dir, "wrangler.jsonc");
  writeFileSync(path, JSON.stringify(wranglerConfig({ name, entry: entryPath, vars }), null, 2), { mode: 0o600 });
  return path;
}

export const configPath = (name) => join(workDir(name), "wrangler.jsonc");

// The exact command a person runs to set a Worker secret. Wrangler prompts for the value,
// so it goes from their keyboard to Cloudflare and never through a file, a chat or this
// repo's code. The config pins the account.
export function secretCommand(name, secret) {
  assertName(name);
  if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(secret)) throw new Error("bad secret name");
  return `cd gateway && npx wrangler secret put ${secret} --name ${name} --config ${JSON.stringify(configPath(name))}`;
}

export function removeConfig(name) {
  rmSync(workDir(name), { recursive: true, force: true });
}

const wranglerBin = join(gatewayDir, "node_modules", ".bin", "wrangler");
const wranglerOpts = {
  cwd: gatewayDir,
  encoding: "utf8",
  get env() {
    return { ...process.env, CLOUDFLARE_ACCOUNT_ID: accountId(), WRANGLER_SEND_METRICS: "false" };
  },
};
const wrangler = (args, config) => execFileSync(wranglerBin, [...args, "--config", config], { ...wranglerOpts, stdio: ["ignore", "pipe", "pipe"] });
// The async form leaves the event loop running, so sockets can be watched during a deploy.
const wranglerAsync = async (args, config) => (await promisify(execFile)(wranglerBin, [...args, "--config", config], wranglerOpts)).stdout;

const deployedUrl = (name, out) => {
  const m = /https:\/\/[a-z0-9.-]+\.workers\.dev/.exec(out);
  if (!m || !m[0].startsWith(`https://${name}.`)) throw new Error("deploy did not report the expected workers.dev URL");
  return m[0];
};

// Names (never values) of the secrets set on the Worker; empty if it does not exist yet.
export function secretNames(name, run = (args, config) => wrangler(args, config), verify = verifyAccount) {
  verify();
  assertName(name);
  try {
    return JSON.parse(run(["secret", "list", "--format", "json"], configPath(name))).map((x) => x.name);
  } catch {
    return [];
  }
}

// Returns the workers.dev URL. The account is verified on every call.
export function deploy(name, vars) {
  verifyAccount();
  return deployedUrl(name, wrangler(["deploy"], writeConfig(name, vars)));
}

export async function deployAsync(name, vars) {
  verifyAccount();
  return deployedUrl(name, await wranglerAsync(["deploy"], writeConfig(name, vars)));
}

export function destroy(name) {
  verifyAccount();
  assertName(name);
  const config = writeConfig(name, {});
  wrangler(["delete", "--force"], config);
}

// Names of Workers on the target account that start with the prefix. Empty means none remain.
export function remaining(run = (cmd, args) => execFileSync(cmd, args, { encoding: "utf8", env: { ...process.env, CLOUDFLARE_ACCOUNT_ID: accountId() } })) {
  verifyAccount(run);
  const out = run("cf", ["workers", "scripts", "search", "--name", PREFIX]);
  return [...new Set([...out.matchAll(/parley-test-[a-z0-9-]+/g)].map((m) => m[0]))];
}
