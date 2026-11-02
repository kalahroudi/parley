// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Release gate: the DEV_AUTH placeholder must not exist in any form that ships.
//   node scripts/check-dev-auth.mjs [repo-root]
// Fails (exit 1) when
//   - a release configuration (wrangler config, .dev.vars, release workflow or
//     script) sets DEV_AUTH to anything but empty/0/false, or
//   - gateway or dashboard source mentions DEV_AUTH or a `dev-admin`/`dev-user`
//     bearer at all (the code path itself is gone, not just switched off).
// Passes when DEV_AUTH is removed or explicitly disabled in configuration.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const SKIP = new Set(["node_modules", ".git", ".wrangler", "dist"]);
const CONFIG = /^(wrangler\.(jsonc?|toml)|\.dev\.vars.*|.*\.env)$/;
const SOURCE_DIRS = ["gateway/src", "dashboard/src", "dashboard/worker"];
const RELEASE_FILES = [".github/workflows/release.yml", "scripts/release.sh"];
const OFF = new Set(["", "0", "false"]);

function walk(dir, keep) {
  const out = [];
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p, keep));
    else if (keep(name)) out.push(p);
  }
  return out;
}

// Every value DEV_AUTH is given in a config file: `"DEV_AUTH": "1"`, `DEV_AUTH = "1"`, `DEV_AUTH=1`, `DEV_AUTH:1`.
function assigned(text) {
  const vals = [];
  for (const m of text.matchAll(/DEV_AUTH["']?\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|([^\s,}]*))/g)) vals.push((m[1] ?? m[2] ?? m[3] ?? "").trim());
  return vals;
}

export function check(root) {
  const problems = [];
  const configs = [...walk(root, (n) => CONFIG.test(n)), ...RELEASE_FILES.map((f) => join(root, f)).filter(existsSync)];
  for (const f of configs) {
    const text = readFileSync(f, "utf8");
    if (!text.includes("DEV_AUTH")) continue;
    const vals = assigned(text);
    // A mention with no readable value (for example a wrangler `secrets` list) counts as enabled.
    if (vals.length === 0 || vals.some((v) => !OFF.has(v.toLowerCase()))) problems.push(`${relative(root, f)}: DEV_AUTH is enabled`);
  }
  for (const d of SOURCE_DIRS) {
    for (const f of walk(join(root, d), () => true)) {
      if (/DEV_AUTH|dev-admin|dev-user/.test(readFileSync(f, "utf8"))) problems.push(`${relative(root, f)}: development auth path present`);
    }
  }
  return problems;
}

if (process.argv[1] && basename(process.argv[1]) === "check-dev-auth.mjs") {
  const root = process.argv[2] ?? join(fileURLToPath(import.meta.url), "..", "..");
  const problems = check(root);
  if (problems.length) {
    console.error(`DEV_AUTH release gate failed:\n${problems.map((p) => `  ${p}`).join("\n")}`);
    process.exit(1);
  }
  console.log("DEV_AUTH release gate: ok");
}
