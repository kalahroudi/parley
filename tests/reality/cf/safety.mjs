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

export const ACCOUNT_ID = "b891d46224e846153205dd9144c205c9";
export const PREFIX = "parley-test-";
const NAME = /^parley-test-[a-z0-9][a-z0-9-]{0,40}$/;
const here = fileURLToPath(new URL(".", import.meta.url));
const gatewayDir = resolve(here, "..", "..", "..", "gateway");

export function assertName(name) {
  if (!NAME.test(name)) throw new Error(`refusing Worker name ${JSON.stringify(name)}: must match ${NAME}`);
  return name;
}

// `cf accounts list` must show the target account; the login has two accounts and
// the default must never decide. Aborts otherwise.
export function verifyAccount(run = (cmd, args) => execFileSync(cmd, args, { encoding: "utf8" })) {
  let ids;
  try {
    ids = JSON.parse(run("cf", ["accounts", "list"])).map((a) => a.id);
  } catch (err) {
    throw new Error(`cannot verify the Cloudflare account: ${err.message}`);
  }
  if (!ids.includes(ACCOUNT_ID)) throw new Error(`target account ${ACCOUNT_ID.slice(0, 8)}... not found in \`cf accounts list\`; aborting`);
  return true;
}

// A generated wrangler config outside the repo tree. The account is pinned, only
// workers.dev is enabled (no routes, domains or previews), and logging is off.
export function wranglerConfig({ name, entry, vars }) {
  assertName(name);
  return {
    name,
    account_id: ACCOUNT_ID,
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
  const dir = workDir(name);
  const path = join(dir, "wrangler.jsonc");
  writeFileSync(path, JSON.stringify(wranglerConfig({ name, entry: entryPath, vars }), null, 2), { mode: 0o600 });
  return path;
}

export function removeConfig(name) {
  rmSync(workDir(name), { recursive: true, force: true });
}

const wranglerBin = join(gatewayDir, "node_modules", ".bin", "wrangler");
const wranglerOpts = {
  cwd: gatewayDir,
  encoding: "utf8",
  env: { ...process.env, CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID, WRANGLER_SEND_METRICS: "false" },
};
const wrangler = (args, config) => execFileSync(wranglerBin, [...args, "--config", config], { ...wranglerOpts, stdio: ["ignore", "pipe", "pipe"] });
// The async form leaves the event loop running, so sockets can be watched during a deploy.
const wranglerAsync = async (args, config) => (await promisify(execFile)(wranglerBin, [...args, "--config", config], wranglerOpts)).stdout;

const deployedUrl = (name, out) => {
  const m = /https:\/\/[a-z0-9.-]+\.workers\.dev/.exec(out);
  if (!m || !m[0].startsWith(`https://${name}.`)) throw new Error("deploy did not report the expected workers.dev URL");
  return m[0];
};

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
export function remaining(run = (cmd, args) => execFileSync(cmd, args, { encoding: "utf8", env: { ...process.env, CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID } })) {
  verifyAccount(run);
  const out = run("cf", ["workers", "scripts", "search", "--name", PREFIX]);
  return [...new Set([...out.matchAll(/parley-test-[a-z0-9-]+/g)].map((m) => m[0]))];
}
