// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T107: runs the Go end-to-end trust tests (enroll, approve, root-signed binding,
// revoke, signed list distribution, send refusal, stale list, clock set back,
// recovery code) against the real gateway Worker under `wrangler dev`, so the
// Go client and gateway/src cannot drift apart. `go test ./internal/trust` runs
// the same tests against an in-process fake without needing Node.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startGateway } from "./harness/wrangler.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const haveGo = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const haveGateway = existsSync(join(root, "gateway", "node_modules", ".bin"));
// Missing tools skip locally and fail under CI, like `make test-go`.
const skip = !haveGo ? "go not installed" : !haveGateway ? "gateway dependencies not installed (cd gateway && npm ci)" : false;
const needs = skip && !process.env.CI ? { skip } : {};

test("trust: enroll, approve, revoke and stale-list behavior against the real gateway", needs, async () => {
  const gw = await startGateway(join(root, "gateway"));
  try {
    const url = gw.url;
    const r = spawnSync("go", ["test", "-race", "-count=1", "-v", "./internal/trust"], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, PARLEY_TEST_GATEWAY_HTTP: url },
    });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    // Guard against a silent skip: the scenarios must have run, not been skipped.
    for (const name of ["TestEndToEnd", "TestRootClockWentBackwards", "TestForgedListIsIgnored"]) {
      assert.match(r.stdout, new RegExp(`--- PASS: ${name}\\b`));
    }
  } finally {
    await gw.stop({ clean: true });
  }
});
