// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const hasGo = spawnSync("go", ["version"]).status === 0;
const exe = process.platform === "win32" ? ".exe" : "";

// The `go install` and source channels: both programs build and install from the module path, run, and, being
// builds without a release version, say so and never replace themselves.
test("go install builds both programs, which run and refuse to self-update", { skip: !hasGo && "go not installed" }, () => {
  const bin = mkdtempSync(join(tmpdir(), "parley-gobin-"));
  const home = mkdtempSync(join(tmpdir(), "parley-home-"));
  const env = { ...process.env, GOBIN: bin, GOFLAGS: "-mod=readonly", PARLEY_HOME: home };
  const inst = spawnSync("go", ["install", "./cmd/parleyd", "./cmd/parley-cli"], { cwd: root, env, encoding: "utf8" });
  assert.equal(inst.status, 0, inst.stderr);
  const daemon = spawnSync(join(bin, "parleyd" + exe), ["--version"], { env, encoding: "utf8" });
  assert.equal(daemon.status, 0);
  assert.equal(daemon.stdout.trim(), "parleyd dev");
  const cli = spawnSync(join(bin, "parley-cli" + exe), ["--version"], { env, encoding: "utf8" });
  assert.equal(cli.stdout.trim(), "parley-cli dev");
  const upd = spawnSync(join(bin, "parley-cli" + exe), ["update", "apply"], { env, encoding: "utf8" });
  assert.equal(upd.status, 1);
  assert.match(upd.stderr, /not a release build/);
  assert.equal(upd.stdout, "");
});
