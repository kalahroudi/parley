// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, extname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const HEADER =
  "// Copyright 2026 The Parley Authors\n// SPDX-License-Identifier: Apache-2.0\n";
const SKIP = new Set(["node_modules", ".git", "dist", ".wrangler"]);

function sources(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...sources(p));
    else if ([".go", ".ts", ".mjs"].includes(extname(p))) out.push(p);
  }
  return out;
}

test("expected layout exists", () => {
  for (const p of [
    "cmd/parleyd/main.go",
    "cmd/parley-cli/main.go",
    "internal",
    "gateway/package.json",
    "gateway/src/index.ts",
    "admin/package.json",
    "admin/src/index.ts",
    "tests",
    "CONTRIBUTING.md",
    "LICENSE",
  ]) {
    assert.ok(existsSync(join(root, p)), `missing ${p}`);
  }
});

test("every source file has the license header", () => {
  const files = sources(root);
  assert.ok(files.length > 0);
  for (const f of files) {
    assert.ok(readFileSync(f, "utf8").startsWith(HEADER), `no header: ${f}`);
  }
});

test("package manifests declare Apache-2.0", () => {
  for (const d of ["gateway", "admin"]) {
    const pkg = JSON.parse(readFileSync(join(root, d, "package.json"), "utf8"));
    assert.equal(pkg.license, "Apache-2.0");
  }
});
