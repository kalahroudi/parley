// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T509 journey tests that are not written yet: blocked by unbuilt product (first group) or unblocked (last group). Each is named after the journey row
// in tests/journeys.md (named by journey, because a planned row's id must not appear in any test) and fails CI once the task that builds it is ticked, so a ticked task cannot leave its
// journey test unwritten.

import { pending } from "./harness/pending.mjs";

pending(
  "journey A: sign-up, IdP connection, users and groups, retention mode, the free tier of 3 devices and the install command with the root fingerprint, driven through the admin page",
  "T501",
  "the admin page does not exist (the gateway has the admin API for groups, retention and enrollment, but no setup flow or install command)",
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

// The journeys with nothing blocking them that have no executable test yet. T509 stays open until each is written;
// ticking T509 fails these.
pending("journey B: `login --root <fingerprint>` through SSO and admin approval to a device that shows online; a wrong fingerprint is refused", "T509", "not yet an executable test, unblocked");
pending("journey C: publish a card with visibility, groups and allowlist; the secrets lint rejects a secret; several bots on one daemon", "T509", "not yet an executable test, unblocked");
pending("journey D: find_agents and send_task / get_task between two daemons with binding and revocation checked before send", "T509", "not yet an executable test, unblocked");
pending("journey E: the full task lifecycle with encrypted status text and the FAILED, CANCELED and REJECTED terminals", "T509", "not yet an executable test, unblocked");
pending("journey F: offline target, busy queue of 5, not permitted and timeout", "T509", "not yet an executable test, unblocked");
pending("journey F: recipient restart loses keys and a resend succeeds, caller disconnected in Strict, stale revocation list refuses send", "T509", "not yet an executable test, unblocked");
pending("journey G: approval none and owner, and the five-minute timeout rejecting the task", "T509", "not yet an executable test, unblocked");
pending("journey G: the approval-gated tool-using skill with the reference reviewer bot, macOS and Linux, and refused on Windows", "T509", "not yet an executable test, unblocked");
pending("journey I: deactivation updates the revocation list, closes sockets, cancels tasks and hides bots at the daemon level, with the 24 h re-validation and 72 h grace", "T509", "not yet an executable test, unblocked (the gateway cascade is tested in gateway/test/offboarding.test.ts; T503 is also open)");
pending("journey B: install from each channel with the checksum and signature verified, using the release verification the updater and channels share", "T504", "no updater or channel verification exists yet");
