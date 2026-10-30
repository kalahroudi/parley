// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const header = (c) =>
  `${c} Copyright 2026 The Parley Authors\n${c} SPDX-License-Identifier: Apache-2.0\n`;
// Comment prefix per source extension. A shebang line may precede the header.
const COMMENT = {
  ".go": "//",
  ".ts": "//",
  ".mts": "//",
  ".cts": "//",
  ".tsx": "//",
  ".js": "//",
  ".mjs": "//",
  ".cjs": "//",
  ".jsx": "//",
  ".sh": "#",
  ".py": "#",
  ".yml": "#",
  ".yaml": "#",
};
const SKIP = new Set(["node_modules", ".git", "dist", ".wrangler"]);

function sources(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...sources(p));
    else if (extname(p) in COMMENT) out.push(p);
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
    const text = readFileSync(f, "utf8").replace(/^#!.*\n/, "");
    assert.ok(text.startsWith(header(COMMENT[extname(f)])), `no header: ${f}`);
  }
});

test("package manifests declare Apache-2.0", () => {
  for (const d of ["gateway", "admin"]) {
    const pkg = JSON.parse(readFileSync(join(root, d, "package.json"), "utf8"));
    assert.equal(pkg.license, "Apache-2.0");
  }
});

test("CI runs on macOS, Linux and Windows and runs Go directly", () => {
  const ci = readFileSync(join(root, ".github/workflows/ci.yml"), "utf8");
  for (const os of ["ubuntu-latest", "macos-latest", "windows-latest"]) {
    assert.ok(ci.includes(os), `CI matrix missing ${os}`);
  }
  assert.ok(ci.includes("go test -race ./..."), "CI must run Go tests directly");
  assert.ok(!ci.includes("make test-go"), "CI must not use the skipping make target");
});

test("make test-go fails instead of skipping when Go is missing under CI", { skip: process.platform === "win32" }, () => {
  const make = spawnSync("sh", ["-c", "command -v make"], { encoding: "utf8" }).stdout.trim();
  if (!make) return;
  // An empty PATH hides go; make is invoked by absolute path.
  const run = (env) =>
    spawnSync(make, ["-s", "test-go", "SHELL=/bin/sh"], {
      cwd: root,
      encoding: "utf8",
      env: { ...env, PATH: "/nonexistent" },
    });
  assert.notEqual(run({ CI: "true" }).status, 0, "must fail under CI");
  assert.equal(run({}).status, 0, "must skip locally");
});
