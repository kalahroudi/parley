// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T307 proves deletion at acknowledgment and TTL for everything the gateway holds today: sealed results in the Task
// DO (gateway/test/retention.acceptance.test.ts). Encrypted FILES are not among them: the plan puts file ciphertext
// in R2 "under random keys through the Worker", but the Worker has no file route and declares no R2 bucket
// (wrangler.jsonc), and no task builds one. The deletion test for files cannot be written before that route exists,
// so it is named here and fails CI once T308 (which verifies R2 deletion) is ticked.
//
// The second is "Queued TTL deletion with a real daemon reconnecting after the TTL receives nothing". The tunnel-level
// reconnect is proven in the gateway suite; a real daemon cannot show it before the walking skeleton (T405), because a
// caller daemon that restarts loses its pending tasks by design, so the case needs a dropped connection on a live
// daemon, which the journey tests are built to produce. It fails once T405 is ticked.

import { pending } from "./harness/pending.mjs";

pending(
  "encrypted files in R2: stored under random keys, deleted at acknowledgment and at the retention TTL, none left in the bucket (and no file name or key in D1, DO storage or logs)",
  "T308",
  "the Worker has no file route and no R2 bucket yet; add the route (and a task for it) before T308 can verify R2 deletion",
);

pending(
  "Queued TTL deletion with a real daemon: its connection drops while a task runs, the target's result is held, the TTL passes, the daemon reconnects and receives nothing, and the task is not completed from stale data",
  "T405",
  "needs the walking-skeleton journey's way to drop a live daemon's connection",
);
