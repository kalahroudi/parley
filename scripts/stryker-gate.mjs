// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Gate for the Stryker report of the tier 1 TypeScript files (scripts/mutation.sh).
//
//   node scripts/stryker-gate.mjs gateway/reports/mutation/mutation.json [src/file.ts ...]
//
// Stryker's own break threshold is computed from Killed and Timeout against the
// ones that counted, and a mutant whose run crashed (RuntimeError) or that did
// not compile (CompileError) is left out of the score. An unverified mutant is
// not a killed one, so only Killed and Timeout pass here.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const OK = new Set(["Killed", "Timeout"]);

// `expected` names the files the run was asked to mutate (as the report writes them): one missing from the report
// was not mutated at all, which would otherwise read as clean.
export function check(report, expected = []) {
  const problems = [];
  for (const f of expected) if (!(f in (report.files ?? {}))) problems.push(`${f} was asked for but is not in the report`);
  for (const [file, f] of Object.entries(report.files ?? {})) {
    for (const m of f.mutants ?? []) {
      if (OK.has(m.status)) continue;
      const at = `${file}:${m.location?.start?.line}:${m.location?.start?.column}`;
      problems.push(`${m.status} ${m.mutatorName} at ${at}${m.statusReason ? ` (${m.statusReason})` : ""}`);
    }
  }
  if (Object.keys(report.files ?? {}).length === 0) problems.push("the report names no mutated file");
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const problems = check(JSON.parse(readFileSync(process.argv[2], "utf8")), process.argv.slice(3));
  for (const p of problems) console.error("stryker gate:", p);
  console.log(`stryker gate: ${problems.length === 0 ? "ok" : problems.length + " problem(s)"}`);
  process.exit(problems.length === 0 ? 0 : 1);
}
