// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T307 proves deletion at acknowledgment and TTL for everything the gateway holds today: sealed results in the Task
// DO (gateway/test/retention.acceptance.test.ts). Encrypted FILES are not among them: the plan puts file ciphertext
// in R2 "under random keys through the Worker", but the Worker has no file route and declares no R2 bucket
// (wrangler.jsonc), and no task builds one. The deletion test for files cannot be written before that route exists,
// so it is named here and fails CI once T308 (which verifies R2 deletion) is ticked.
//
// The second, "Queued TTL deletion with a real daemon reconnecting after the TTL receives nothing", is written (T405):
// tests/slow/queued-ttl.mjs, run by `make queued-ttl` (no CI workflow runs it yet).

import { pending } from "./harness/pending.mjs";

pending(
  "encrypted files in R2: stored under random keys, deleted at acknowledgment and at the retention TTL, none left in the bucket (and no file name or key in D1, DO storage or logs)",
  "T308",
  "the Worker has no file route and no R2 bucket yet; add the route (and a task for it) before T308 can verify R2 deletion",
);
