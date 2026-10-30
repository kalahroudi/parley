# Parley: Specification (MVP)

What Parley must do and what it promises. How it is built is in [plan.md](plan.md); the phased work and acceptance tests are in [tasks.md](tasks.md).

## Goal

Bots owned by different employees find each other and exchange tasks securely on Cloudflare, with task content the platform cannot read and does not keep in readable form. Simple, with nothing a user touches left out.

## Constraints

- Hosted on Cloudflare only (Workers, Durable Objects, D1, R2).
- Open source (Apache 2.0), with no dependency on any app store or platform signing vendor.
- Bots are whatever the customer brings, through three adapters: headless CLI, ACP and API. Vendor terms for those tools are the customer's responsibility, with a notice.
- Platforms: macOS, Linux and Windows. Tool-using skills are unsupported on Windows until a sandbox exists.
- Billing: flat per-device seats via Stripe, enforced only at enrollment.

## Guarantees and non-guarantees

**We guarantee (task content = inputs, results, status text, questions, errors, files)**
- G1: Under the tenant signing root, an active malicious gateway, our staff, or a breach of our storage cannot read or forge task content.
- G2: We do not store readable task content. Ciphertext is deleted per the retention mode.
- G3: Only the intended device can decrypt a task, and only a root-approved caller device can have produced it.
- G4: A revoked or deactivated device receives no new work once the signed revocation list propagates (at most one refresh interval).
- G5: Forward secrecy for task content. Captured ciphertext of tasks the recipient device has already received and processed cannot be decrypted with keys later stolen from the device, assuming the device erased the keys. Replies are protected per message once their keys are erased.

**We do not guarantee (stated in customer docs)**
- Metadata is visible to us: who called which bot, when, state codes, padded size bucket.
- Agent cards (name, description, tags, examples), group names and the audit CSV are plaintext. Owners must not put secrets in them; publishing runs a secrets lint.
- Group-based visibility is decided by the gateway and is advisory. The target daemon enforces the owner's allowlist by identity from the root-signed binding.
- Forward secrecy depends on devices actually erasing used keys. Prekeys live in memory only, but erasure in Go is best effort, and backups, VM memory snapshots and hibernation images void it. Our hardening guide requires full-disk encryption and disabled or encrypted hibernation and swap.
- A prekey that has been issued but not yet used stays valid until it expires (at most the task expiry, default 15 min). A gateway that withholds delivery and keeps captured ciphertext could exploit a device stolen inside that window.
- Signing keys are long-term: theft allows impersonation until revoked, but no decryption of tasks whose keys were erased.
- Plaintext already on a device (bot CLI history, logs, temp files, task results) is outside this guarantee.
- Deleted ciphertext may persist in Cloudflare's 30-day recovery history (verified for SQLite-backed Durable Objects). It is encrypted to keys we never hold, and for processed tasks to keys the device has already erased.
- Retention at endpoints (the bot, its CLI history, the model vendor) is the customer's.
- "Zero retention" is a model-vendor term. Our statement is: "no plaintext task data is held by us; ciphertext is deleted within the configured TTL, subject to Cloudflare's recovery window."
- Anything R2-related is claimed only as "deleted from our bucket" until R2 deletion semantics are verified.


## User journeys

**A. Admin onboarding (~15 min).** Sign up, connect Google, Microsoft or Okta, run `parley-cli admin init` (root key plus recovery code), add users and groups, choose retention mode, subscribe or stay free (3 devices), share the install command with its root fingerprint.

**B. Employee enrollment.** Install through Homebrew, the package repo or the install script (checksum and signature verified against the published release key), then `parley-cli login --root <fingerprint>`, SSO, the browser shows a code and device name, keys are generated, the request waits for admin approval (batch approval is one click on the admin's daemon). Background service starts on boot. `parley-cli test` sends a task to your own bot to prove the full path.

**C. Publish a bot.** Name, description, tags, examples (secrets lint), visibility or allowed groups, owner allowlist, approval mode, concurrency, timeout. Several bots per daemon.

**D. Discover and call.** The caller's bot uses the daemon's MCP tools or CLI: `find_agents`, `send_task`, `get_task(wait_seconds)`, `cancel_task`, `list_tasks`. The daemon verifies the target's root-signed binding and revocation status before sending, and asks the target for a one-time prekey over the live relay. Users see no key prompts. Results are marked untrusted.

**E. Long tasks.** SUBMITTED, WORKING (encrypted status text), INPUT_REQUIRED (encrypted question; reply on the same task), COMPLETED, FAILED, CANCELED, REJECTED.

**F. Not-happy paths.** Offline target (the caller's daemon waits up to the task expiry, then FAILED), busy (queue 5 then REJECTED), not permitted (REJECTED, bot hidden), timeout, recipient restarted and lost its keys (resend), caller disconnected (Strict), revocation list too old.

**G. Approval.** `none` for tool-less skills; `owner` for tool-using skills via `parley-cli approve <id>`; no answer in 5 min means REJECTED.

**H. Pods.** Admin-minted single-use token, headless device, named service owner, binding signed by the admin's daemon; ideal for Strict.

**I. Offboarding.** Deactivation cascades: the root-signed revocation list is updated, sockets close, tasks are canceled, bots hidden. Sessions re-validate against the IdP every 24 h (72 h grace if the IdP is down).

**J. Updates.** Auto-update verified against the project's own pinned release key, with a pin-to-version option; protocol version in the handshake.

**K. Billing.** Stripe Checkout and Portal; seat limit enforced only at enrollment; live tunnels are never cut.

**L. Owner and security-team views.** Per-bot call log (metadata), admin kill-switch with a reason, metadata audit CSV, tenant export and deletion.



## Interoperability

Discovery and task lifecycle use A2A v1.0 (card at the well-known path, `TASK_STATE_*` states including INPUT_REQUIRED, list, cancel, subscribe; push notifications unsupported). Message parts are opaque ciphertext parts. A standard third-party A2A client can reach the transport but cannot read content; content requires our daemon or SDK. CI jobs use a headless enrolled device. We claim "A2A v1.0 transport and lifecycle with encrypted message parts", not content interoperability.


## Out of scope for the MVP, and what users get instead

Token streaming (encrypted status text instead). Gateway-side queueing of tasks for offline bots (the sender's daemon waits and retries instead). SCIM and IdP groups (admin-managed groups). Semantic search (name, description and tag filter). Gateway-side content DLP (impossible with E2E; daemon-side hooks later). MDM policy files. A real sandbox for tool-using skills (approval-gated and labeled until proven; unsupported on Windows). Cross-device bot sync (a bot is bound to one device).


## Compliance and operations

Tenant export and deletion, subprocessor list (Cloudflare, Stripe), data-processing terms, no operator access to content. Counsel reviews every data-handling claim, including the wording in "Guarantees and non-guarantees".


## Open decisions

- Admin approval friction for new devices (default: manual batch approval) versus the labeled auto-approve option.
- Queued default TTL (1 h proposed).
