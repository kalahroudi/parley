// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T107: runs the Go end-to-end trust tests (enroll, approve, root-signed binding,
// revoke, signed list distribution, send refusal, stale list, clock set back,
// recovery code) against the real gateway Worker under `wrangler dev`, so the
// Go client and gateway/src cannot drift apart. `go test ./internal/trust` runs
// the same tests against an in-process fake without needing Node.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startGateway } from "./harness/gateway.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const haveGo = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const haveGateway = existsSync(join(root, "gateway", "node_modules", ".bin"));
// Missing tools skip locally and fail under CI, like `make test-go`.
const skip = !haveGo ? "go not installed" : !haveGateway ? "gateway dependencies not installed (cd gateway && npm ci)" : false;
const needs = skip && !process.env.CI ? { skip } : {};

test("trust: enroll, approve, revoke and stale-list behavior against the real gateway", needs, async () => {
  // The Go tests name their tenants <prefix>-1, <prefix>-2, ...; the admin of each signs in through the mock IdP.
  const prefix = `trust${randomBytes(4).toString("hex")}`;
  const tenants = Array.from({ length: 20 }, (_, i) => `${prefix}-${i + 1}`);
  const admins = tenants.map((t) => `${t}:admin@example.test`).join(",");
  const gw = await startGateway({ admins, userDomains: tenants.map((t) => `${t}:acme.test`).join(",") });
  try {
    const url = gw.url;
    // Async: the Go tests sign in through the mock IdP, which lives in this process.
    const r = await new Promise((resolve, reject) => {
      const p = spawn("go", ["test", "-race", "-count=1", "-v", "./internal/trust"], {
        cwd: root,
        env: { ...process.env, PARLEY_TEST_GATEWAY_HTTP: url, PARLEY_TEST_TENANT_PREFIX: prefix },
      });
      let stdout = "";
      let stderr = "";
      p.stdout.on("data", (d) => (stdout += d));
      p.stderr.on("data", (d) => (stderr += d));
      p.on("error", reject);
      p.on("close", (status) => resolve({ status, stdout, stderr }));
    });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    // Guard against a silent skip: the scenarios must have run, not been skipped.
    for (const name of ["TestEndToEnd", "TestRootClockWentBackwards", "TestForgedListIsIgnored"]) {
      assert.match(r.stdout, new RegExp(`--- PASS: ${name}\\b`));
    }
  } finally {
    await gw.close();
  }
});
