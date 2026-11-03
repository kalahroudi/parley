// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: { bindings: { DEV_AUTH: "1" } },
    }),
  ],
  test: {
    // Every durable storage write costs ~25 ms on Windows CI runners (~0.5 ms on
    // Linux and macOS), so tests that do many writes (20 reconnects, the pending
    // queue, the task state machine) can take 6-12 s there against vitest's 5 s
    // default, and a timed-out test leaves its sockets and objects busy for the
    // tests after it. 30 s is about 3x the slowest observed run; a real hang still
    // fails in 30 s. One value on every OS, so the suite behaves the same everywhere.
    testTimeout: 30_000,
    coverage: {
      // Workers code runs in workerd, where only the istanbul provider works.
      provider: "istanbul",
      include: ["src/**"],
      // auth.ts and oidc.ts are Web-API-only and are tested with the mock IdP in
      // tests/gateway-oidc.test.mjs (node:test), which has its own gate; see "make coverage".
      exclude: ["src/auth.ts", "src/oidc.ts"],
      reporter: ["text"],
      // Tier 2 of the plan's coverage policy, enforced on every file.
      // Tier 1 for the task state machine, deadlines and retention logic: 100% of
      // lines, statements, branches and functions, with no exclusions (mutation
      // testing is scripts/mutation-ts.mjs). The glob keeps task.ts out of the tier 2 numbers.
      thresholds: {
        perFile: true,
        lines: 95,
        statements: 95,
        branches: 90,
        functions: 95,
        "src/task.ts": { lines: 100, statements: 100, branches: 100, functions: 100 },
      },
    },
  },
});
