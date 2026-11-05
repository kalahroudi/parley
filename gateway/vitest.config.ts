// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      // The per-device limits are raised for every suite but ratelimit.test.ts, which sets its own.
      // Tests mint admin sessions for admin@example.test in tenants named <prefix><n>.
      miniflare: { bindings: { ADMINS: ["ten", "dir", "ses", "a2a", "dev"].flatMap((p) => Array.from({ length: 400 }, (_, i) => `${p}${i + 1}:admin@example.test`)).concat(["tx:root@example.test"]).join(","), RATE_TASK_PER_MIN: "100000", RATE_MESSAGE_PER_MIN: "100000", RATE_FIND_PER_MIN: "100000", RATE_CONNECT_PER_MIN: "100000" } },
    }),
  ],
  test: {
    // Durable Object storage writes cost ~25 ms each on Windows runners (see the soak note in ci.yml);
    // the lifecycle tests make dozens, so the 5 s default is too tight there.
    // Run in parallel on a 2-core runner, a test there has been seen to take 40 s that takes 3 s elsewhere (a
    // different test on each run; main fails the same way), so Windows gets 120 s. Other OSes keep 30 s.
    testTimeout: process.platform === "win32" ? 120_000 : 30_000,
    coverage: {
      // Workers code runs in workerd, where only the istanbul provider works.
      provider: "istanbul",
      include: ["src/**"],
      // auth.ts and oidc.ts are Web-API-only and are tested with the mock IdP in
      // tests/gateway-oidc.test.mjs (node:test), which has its own gate; see "make coverage".
      exclude: ["src/auth.ts", "src/oidc.ts"],
      reporter: ["text"],
      // Tier 2 of the plan's coverage policy, enforced on every file.
      // Tier 1 for the task state machine, deadlines and retention logic, and the ACL evaluation (acl.ts): 100% of
      // lines, statements, branches and functions, with no exclusions (mutation
      // testing is scripts/mutation-ts.mjs). The globs keep task.ts, parts.ts and acl.ts out of the tier 2 numbers.
      thresholds: {
        perFile: true,
        lines: 95,
        statements: 95,
        branches: 90,
        functions: 95,
        "src/task.ts": { lines: 100, statements: 100, branches: 100, functions: 100 },
        "src/device.ts": { lines: 100, statements: 100, branches: 100, functions: 100 },
        // Tier 1 for what the gateway checks about a sealed part before it relays it.
        "src/parts.ts": { lines: 100, statements: 100, branches: 100, functions: 100 },
        "src/acl.ts": { lines: 100, statements: 100, branches: 100, functions: 100 },
        // Tier 1 for the rate limiter (login, session and per-device budgets).
        "src/ratelimit.ts": { lines: 100, statements: 100, branches: 100, functions: 100 },
        // Tier 1 for device authentication (challenge, token, and what each connection must present).
        "src/connect.ts": { lines: 100, statements: 100, branches: 100, functions: 100 },
        // Tier 1 for the frames the gateway parses before it relays them.
        "src/protocol.ts": { lines: 100, statements: 100, branches: 100, functions: 100 },
        // Tier 1 for the device sign-in confirmation (the page that shows the code, and the form that confirms it).
        "src/login.ts": { lines: 100, statements: 100, branches: 100, functions: 100 },
      },
    },
  },
});
