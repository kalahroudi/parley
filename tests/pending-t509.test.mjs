// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T509 journey tests that cannot be written until the product they drive exists. Each is named after the journey row
// in tests/journeys.md (named by journey, because a planned row's id must not appear in any test) and fails CI once the task that builds it is ticked, so a ticked task cannot leave its
// journey test unwritten.

import { pending } from "./harness/pending.mjs";

pending(
  "journey A: sign-up, IdP connection, users and groups, retention mode, the free tier of 3 devices and the install command with the root fingerprint, driven through the admin page",
  "T501",
  "the admin page does not exist (the gateway has the admin API for groups, retention and enrollment, but no setup flow or install command)",
);
pending(
  "journeys A and K: a fourth device is refused at enrollment on the free tier, a subscription raises the limit, and a live tunnel is never cut",
  "T502",
  "there is no seat limit, subscription or Stripe code yet",
);
pending(
  "journey K: Stripe Checkout and Portal in test mode drive the seat limit",
  "T510",
  "billing webhooks are not built or tested against Stripe test events yet",
);
pending(
  "journey J: the daemon accepts an update signed by the pinned release key, rejects any other and a rollback, holds a pinned version, and the handshake carries the protocol version",
  "T504",
  "the daemon has no updater; internal/release only signs and verifies release files",
);
pending(
  "journey B: install from each channel with checksum and signature verified, and the service starts on boot",
  "T511",
  "no distribution channel exists yet to install from",
);
pending(
  "journey L: the owner's per-bot call log and the admin kill-switch with a reason",
  "T501",
  "the gateway has no per-bot call log view and no kill-switch route; the audit CSV, export and tenant deletion exist (gateway/test/offboarding.test.ts)",
);
