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
        "src/device.ts": { lines: 100, statements: 100, branches: 100, functions: 100 },
      },
    },
  },
});
