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
    // Normalise CRLF so a Windows checkout with autocrlf still passes.
    const text = readFileSync(f, "utf8").replace(/\r\n/g, "\n").replace(/^#!.*\n/, "");
    assert.ok(text.startsWith(header(COMMENT[extname(f)])), `no header: ${f}`);
  }
});

test(".gitattributes forces LF line endings", () => {
  const attrs = readFileSync(join(root, ".gitattributes"), "utf8");
  assert.match(attrs, /^\*\s+.*\beol=lf\b/m);
});

test("no source file contains CR line endings", () => {
  for (const f of sources(root)) {
    assert.ok(!readFileSync(f, "utf8").includes("\r"), `CR in: ${f}`);
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
  const matrix = ci.match(/^\s*os:\s*\[([^\]]*)\]/m);
  assert.ok(matrix, "CI must define an os matrix");
  for (const os of ["ubuntu-latest", "macos-latest", "windows-latest"]) {
    assert.ok(matrix[1].includes(os), `CI matrix missing ${os}`);
  }
  assert.match(ci, /^\s*fail-fast:\s*false\s*$/m, "one OS failing must not hide the others");
  assert.match(ci, /^\s*run:\s*go vet \.\/\.\.\.\s*$/m, "CI must run go vet");
  assert.match(ci, /^\s*run:\s*go test -race \.\/\.\.\.\s*$/m, "CI must run Go tests directly");
  assert.match(ci, /^\s*run:\s*node --test\b/m, "CI must run the layout tests");
  assert.ok(!/^\s*run:.*\bmake\b/m.test(ci), "CI must not use the skipping make target");
});

test("make test-go fails instead of skipping when Go is missing under CI", { skip: process.platform === "win32" }, (t) => {
  const make = spawnSync("sh", ["-c", "command -v make"], { encoding: "utf8" }).stdout.trim();
  if (!make) return t.skip("make not installed");
  // An empty PATH hides go; make is invoked by absolute path.
  const run = (env) =>
    spawnSync(make, ["-s", "test-go", "SHELL=/bin/sh"], {
      cwd: root,
      encoding: "utf8",
      env: { ...env, PATH: "/nonexistent" },
    });
  const ci = run({ CI: "true" });
  assert.notEqual(ci.status, 0, "must fail under CI");
  assert.match(ci.stderr, /go not installed in CI/);
  const local = run({});
  assert.equal(local.status, 0, "must skip locally");
  assert.match(local.stdout, /skipping/);
});
