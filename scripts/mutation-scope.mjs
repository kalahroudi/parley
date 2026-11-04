// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Chooses what scripts/mutation.sh mutates, and fails closed.
//   node scripts/mutation-scope.mjs <all|changed> [base]      (run from the repo root)
// Prints JSON { scope, reason, packages, files } on stdout: the tier 1 Go packages
// and tier 1 gateway files to mutate. "changed" narrows a pull request to the code
// it touches, but only when it can PROVE what changed. If the merge base with `base`
// cannot be computed (a shallow checkout, a missing ref) or the diff fails, the
// scope is the full one, with the reason printed on stderr. It never skips.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { owned } from "./mutation-gate.mjs";
import { fileURLToPath } from "node:url";

// A change to any of these can weaken the gate for every package.
const GATE = /^(go\.mod|go\.sum|tests\/coverage\/|scripts\/(mutation|stryker-gate|malgw)|\.github\/workflows\/(ci|mutation)\.yml|gateway\/(stryker\.config\.json|tsconfig[^/]*\.json|vitest\.(mutation\.)?config\.ts|package(-lock)?\.json))/;

const git = (cwd, ...a) => execFileSync("git", a, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

// `owns(pkg)` says whether this runner owns any Go file of the package (see mutation-gate.mjs): a runner has
// nothing to judge in a package whose files all belong to an earlier one, so it skips it, which keeps the
// macOS and Windows runs to the few packages with OS-specific files.
export function select({ scope, base = "origin/main", pkgs: all, files, cwd = ".", owns = () => true }) {
  const pkgs = all.filter(owns);
  const run = (...a) => git(cwd, ...a);
  const full = (reason) => ({ scope: "all", reason, packages: pkgs, files });
  if (scope === "all") return full("full run requested");
  if (scope !== "changed") throw new Error("MUTATION_SCOPE must be all or changed");
  let changed;
  try {
    const mb = run("merge-base", base, "HEAD");
    changed = run("diff", "--name-only", "--no-renames", mb, "HEAD").split("\n").filter(Boolean);
  } catch (e) {
    return full(`cannot compute the changes since ${base} (${String(e.stderr || e.message).trim().split("\n")[0]}); running everything`);
  }
  const gate = changed.find((f) => GATE.test(f));
  if (gate) return full(`${gate} is part of the mutation gates; running everything`);
  const packages = pkgs.filter((p) => changed.some((f) => f.startsWith(`${p}/`)));
  // A gateway test helper (anything in gateway/test that is not a *.test.ts) is shared by every test.
  const helper = changed.find((f) => /^gateway\/test\//.test(f) && !/\.test\.ts$/.test(f));
  const tests = changed.filter((f) => /^gateway\/test\/.*\.test\.ts$/.test(f));
  const tsFiles = files.filter((f) => {
    if (helper || changed.includes(f)) return true;
    const stem = f.replace(/^gateway\//, "").replace(/\.ts$/, ""); // src/acl
    // A changed test counts when it imports the file: that test is what kills its mutants. A test that
    // cannot be read (deleted) counts for every file.
    return tests.some((t) => {
      try {
        return run("show", `HEAD:${t}`).includes(`${stem}"`) || run("show", `HEAD:${t}`).includes(`${stem}'`);
      } catch {
        return true;
      }
    });
  });
  return { scope: "changed", reason: `${changed.length} file(s) changed since ${base}`, packages, files: tsFiles };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const pkgs = JSON.parse(readFileSync("tests/coverage/tiers.json", "utf8")).tiers["1"].packages;
  const files = JSON.parse(readFileSync("tests/coverage/gateway-tier1.json", "utf8")).files;
  const [goos, goarch] = execFileSync("go", ["env", "GOOS", "GOARCH"], { encoding: "utf8" }).split("\n");
  try {
    const r = select({ scope: process.argv[2] ?? "all", base: process.argv[3], pkgs, files, owns: (p) => owned(p, { goos, goarch }).size > 0 });
    console.error(`mutation scope: ${r.scope} (${r.reason})`);
    console.log(JSON.stringify(r));
  } catch (e) {
    console.error(e.message);
    process.exit(2);
  }
}
