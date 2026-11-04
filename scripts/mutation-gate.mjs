// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Gate for the gremlins results of one tier 1 Go package (scripts/mutation.sh).
//
//   node scripts/mutation-gate.mjs <package> <gremlins.json> [--stale]
//
// Every mutant must be KILLED (or not viable, which means it does not compile, or timed out, which
// means the tests hung on it and so did not pass).
// A mutant that lived or was not covered by any test fails the gate
// unless tests/coverage/mutation-allowlist.json names it, with a reason, so a
// survivor is never silent and the efficacy threshold never has to be lowered.
// With --stale (a full run) an allowlist entry that no longer matches a mutant
// also fails, so the list cannot outlive the code it excuses.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

// A timed-out mutant made the tests hang or run past 20 times their normal time, so they did not pass: it is
// detected, as in Stryker, PIT and mutmut. (Which mutants time out varies with the runner, so listing them
// by name would make the stale check flaky.)
const OK = new Set(["KILLED", "NOT VIABLE", "TIMED OUT"]);

// The CI runners, in the order that decides who owns a file built on several of them. Gremlins
// parses every .go file whatever its build constraints, so on the wrong OS a mutant in
// lock_windows.go is "not covered". Each file is therefore judged on the first runner that builds it
// (the runner of its own OS for OS-specific code), never allowlisted per mutant for being foreign.
export const RUNNERS = [
  { goos: "linux", goarch: "amd64" },
  { goos: "darwin", goarch: "arm64" },
  { goos: "windows", goarch: "amd64" },
];

// The non-test Go files of pkg that build for a target (what `go build` would compile).
export function built(pkg, { goos, goarch }, cwd = ".") {
  const out = execFileSync("go", ["list", "-f", '{{range .GoFiles}}{{.}}{{"\\n"}}{{end}}{{range .CgoFiles}}{{.}}{{"\\n"}}{{end}}', `./${pkg}`], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GOOS: goos, GOARCH: goarch, CGO_ENABLED: "0" },
  });
  return new Set(out.split("\n").filter(Boolean));
}

// The files `here` is responsible for: built on it and on no earlier runner.
export function owned(pkg, here, cwd = ".") {
  const mine = built(pkg, here, cwd);
  for (const r of RUNNERS) {
    if (r.goos === here.goos && r.goarch === here.goarch) break;
    for (const f of built(pkg, r, cwd)) mine.delete(f);
  }
  return mine;
}

// result is the parsed gremlins -o file; allow the "go" array of the allowlist.
// `own` (a Set of file names) limits the check to the files this runner owns; without it every file counts.
export function check(pkg, result, allow, { stale = false, own } = {}) {
  const problems = [];
  const used = new Set();
  const mine = allow.filter((a) => a.package === pkg && (!own || own.has(a.file)));
  for (const a of mine) {
    if (!a.reason || a.reason.trim().length < 20) problems.push(`allowlist entry ${a.file}:${a.line} ${a.type} has no real reason`);
  }
  for (const f of result.files ?? []) {
    for (const m of f.mutations ?? []) {
      if (OK.has(m.status) || (own && !own.has(f.file_name))) continue;
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
  // The runner's own target, from Go itself (GOOS and GOARCH may be overridden by the environment).
  const [goos, goarch] = execFileSync("go", ["env", "GOOS", "GOARCH"], { encoding: "utf8" }).split("\n");
  if (!RUNNERS.some((r) => r.goos === goos && r.goarch === goarch)) {
    console.error(`mutation gate: ${goos}/${goarch} is not a CI runner target (${RUNNERS.map((r) => `${r.goos}/${r.goarch}`).join(", ")})`);
    process.exit(1);
  }
  const own = owned(pkg, { goos, goarch }, root);
  const problems = check(pkg, JSON.parse(readFileSync(file, "utf8")), allow, { stale: flags.includes("--stale"), own });
  for (const p of problems) console.error("mutation gate:", p);
  console.log(`mutation gate ${pkg}: ${problems.length === 0 ? "ok" : problems.length + " problem(s)"}`);
  process.exit(problems.length === 0 ? 0 : 1);
}
