// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Gate for the gremlins results of one tier 1 Go package (scripts/mutation.sh).
//
//   node scripts/mutation-gate.mjs <package> <gremlins.json> [--stale]
//
// Every mutant must be KILLED (or not viable, which means it does not compile).
// A mutant that lived, timed out or was not covered by any test fails the gate
// unless tests/coverage/mutation-allowlist.json names it, with a reason, so a
// survivor is never silent and the efficacy threshold never has to be lowered.
// With --stale (a full run) an allowlist entry that no longer matches a mutant
// also fails, so the list cannot outlive the code it excuses.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const OK = new Set(["KILLED", "NOT VIABLE"]);

// result is the parsed gremlins -o file; allow the "go" array of the allowlist.
export function check(pkg, result, allow, { stale = false } = {}) {
  const problems = [];
  const used = new Set();
  const mine = allow.filter((a) => a.package === pkg);
  for (const a of mine) {
    if (!a.reason || a.reason.trim().length < 20) problems.push(`allowlist entry ${a.file}:${a.line} ${a.type} has no real reason`);
  }
  for (const f of result.files ?? []) {
    for (const m of f.mutations ?? []) {
      if (OK.has(m.status)) continue;
      const i = mine.findIndex((a) => a.file === f.file_name && a.line === m.line && a.type === m.type && a.status === m.status);
      if (i < 0) problems.push(`${m.status} ${m.type} at ${pkg}/${f.file_name}:${m.line}:${m.column}`);
      else used.add(i);
    }
  }
  if (stale) mine.forEach((a, i) => { if (!used.has(i)) problems.push(`stale allowlist entry ${pkg}/${a.file}:${a.line} ${a.type} ${a.status}`); });
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [pkg, file, ...flags] = process.argv.slice(2);
  const root = join(fileURLToPath(import.meta.url), "..", "..");
  const allow = JSON.parse(readFileSync(join(root, "tests/coverage/mutation-allowlist.json"), "utf8")).go;
  const problems = check(pkg, JSON.parse(readFileSync(file, "utf8")), allow, { stale: flags.includes("--stale") });
  for (const p of problems) console.error("mutation gate:", p);
  console.log(`mutation gate ${pkg}: ${problems.length === 0 ? "ok" : problems.length + " problem(s)"}`);
  process.exit(problems.length === 0 ? 0 : 1);
}
