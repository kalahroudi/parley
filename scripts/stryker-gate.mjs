// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Reads gateway/reports/mutation/mutation.json (after `stryker run`) and fails on
// any mutant that is not Killed or Timeout. Stryker's own break threshold ignores
// mutants that errored (for example one that stops the module from loading) and
// ignored ones, so a defence could go untested while the score still reads 100.
//   node scripts/stryker-gate.mjs [report.json]
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export function bad(report) {
  const out = [];
  for (const [file, f] of Object.entries(report.files)) {
    for (const m of f.mutants) if (m.status !== "Killed" && m.status !== "Timeout") out.push(`${file}:${m.location.start.line} ${m.mutatorName} ${m.status}`);
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const path = process.argv[2] ?? join(fileURLToPath(import.meta.url), "..", "..", "gateway", "reports", "mutation", "mutation.json");
  const problems = bad(JSON.parse(readFileSync(path, "utf8")));
  if (problems.length) {
    console.error(`Stryker gate failed; every mutant must be killed:\n${problems.map((p) => `  ${p}`).join("\n")}`);
    process.exit(1);
  }
  console.log("Stryker gate: every mutant killed or timed out");
}
