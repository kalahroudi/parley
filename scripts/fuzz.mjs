// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Runs every fuzz target in scripts/fuzz-targets.txt, one at a time (Go allows
// one -fuzz target per invocation).
//
//   node scripts/fuzz.mjs smoke   each target for its listed seconds: CI, every push, all OSes
//   node scripts/fuzz.mjs long    each target for FUZZTIME (default 10m): make fuzz-long
//
// Long run: 10 targets x 10 minutes is about 1 hour 45 minutes of wall clock.
// Set FUZZTIME=30m for a release run. A crashing input is written to
// <package>/testdata/fuzz/<target>/ by Go: commit it as a regression seed with
// the fix. The summary at the end is the record to paste into the pull request.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const mode = process.argv[2];
if (mode !== "smoke" && mode !== "long") {
  console.error("usage: fuzz.mjs smoke|long");
  process.exit(2);
}
const targets = readFileSync(join(root, "scripts", "fuzz-targets.txt"), "utf8")
  .split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).map((l) => l.split(/\s+/));
const fuzztime = process.env.FUZZTIME || "10m";

const rows = [];
for (const [pkg, name, smoke] of targets) {
  const t = mode === "long" ? fuzztime : smoke;
  console.log(`\n== ${pkg} ${name} for ${t}`);
  const r = spawnSync("go", ["test", pkg, "-run", "^$", "-fuzz", `^${name}$`, "-fuzztime", t], { cwd: root, encoding: "utf8", maxBuffer: 1 << 28 });
  const out = (r.stdout ?? "") + (r.stderr ?? "");
  const execs = [...out.matchAll(/execs: (\d+)/g)].pop()?.[1] ?? "?";
  const ran = /fuzz: elapsed/.test(out);
  const ok = r.status === 0 && ran;
  if (!ok) console.log(out.split("\n").slice(-40).join("\n"));
  rows.push({ pkg, name, time: t, execs, result: ok ? "no crashes" : ran ? "FAILED" : "DID NOT RUN" });
  console.log(`   ${rows.at(-1).result}, ${execs} execs`);
}
console.log(`\n| package | target | time | execs | result |\n|---|---|---|---|---|`);
for (const r of rows) console.log(`| ${r.pkg} | ${r.name} | ${r.time} | ${r.execs} | ${r.result} |`);
process.exit(rows.every((r) => r.result === "no crashes") ? 0 : 1);
