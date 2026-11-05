// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Stryker (stryker.config.json) runs only the tests of the mutated tier 1 modules.
import { defineConfig, mergeConfig } from "vitest/config";
import base from "./vitest.config";

export default mergeConfig(base, defineConfig({ test: { include: ["test/task.test.ts", "test/device.test.ts", "test/parts.test.ts", "test/acl.test.ts", "test/ratelimit.test.ts", "test/connect.test.ts", "test/protocol.test.ts", "test/login.test.ts"], coverage: { enabled: false } } }));
