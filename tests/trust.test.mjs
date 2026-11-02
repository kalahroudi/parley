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
import { existsSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const haveGo = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const haveGateway = existsSync(join(root, "gateway", "node_modules", ".bin"));
// Missing tools skip locally and fail under CI, like `make test-go`.
const skip = !haveGo ? "go not installed" : !haveGateway ? "gateway dependencies not installed (cd gateway && npm ci)" : false;
const needs = skip && !process.env.CI ? { skip } : {};

const freePort = () =>
  new Promise((resolve, reject) => {
    const s = createServer().once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

function kill(child) {
  try {
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    else process.kill(-child.pid, "SIGKILL");
  } catch {}
}

test("trust: enroll, approve, revoke and stale-list behavior against the real gateway", needs, async () => {
  const port = await freePort();
  const gw = spawn("npx", ["wrangler", "dev", "--port", String(port), "--var", "DEV_AUTH:1"], {
    cwd: join(root, "gateway"),
    stdio: "ignore",
    shell: process.platform === "win32",
    detached: process.platform !== "win32",
  });
  try {
    const url = `http://127.0.0.1:${port}`;
    const end = Date.now() + 60000;
    for (;;) {
      if (gw.exitCode !== null) throw new Error("wrangler dev exited early");
      if (await fetch(`${url}/healthz`).then((r) => r.ok, () => false)) break;
      if (Date.now() > end) throw new Error("gateway did not start");
      await new Promise((r) => setTimeout(r, 200));
    }
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
    kill(gw);
  }
});
