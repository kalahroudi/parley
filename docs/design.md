# Parley: Secure Comms + Discovery Design (v4, end-to-end encrypted, no plaintext retention)

Goal: bots owned by different employees find each other and exchange tasks securely on Cloudflare, with task content the platform cannot read and does not keep in readable form. Simple, with nothing a user touches left out.

Decisions carried forward: Cloudflare only (Workers, three Durable Object classes, D1, R2). Daemon = connector and gatekeeper; bots are whatever the customer brings (API, headless CLI, ACP adapters). Vendor terms are the customer's responsibility, with a notice. Flat per-device seats via Stripe, enforced only at enrollment. Open source, with no dependency on any app store or platform signing vendor.

## 0. What changed from v3
1. End-to-end encryption is mandatory and always on, using HPKE plus signed transcripts (section 3).
2. A tenant signing root is in the MVP, so even a malicious gateway cannot substitute device keys. Trust-on-first-use is removed.
3. Two retention modes: Strict (pass-through, no buffering) and Queued (short-lived ciphertext).
4. Every caller is a device with keys. Keyless personal tokens are dropped.
5. Claims are reworded to what we can honestly prove (section 1).
6. Forward secrecy through on-demand one-time prekeys is in the MVP: tasks already processed stay unreadable even if a device is stolen later.
7. Offline targets: the sender's daemon waits and retries; the gateway never queues task ciphertext. (A prekey pool at the gateway was rejected after review: more attack surface and no real benefit.)

## 1. Guarantees and non-guarantees

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

## 2. What we ship
1. **Daemon (Go; macOS, Linux, Windows).** Outbound WSS only, 1..n bots, verification of bindings, signatures and envelopes, owner policy, adapters, crypto module, caller interface (local MCP server and CLI over an OS-user-restricted socket), local replay table.
2. **Gateway Worker (TypeScript).** A2A v1.0 transport and lifecycle, OIDC login (Google, Microsoft Entra, generic OIDC), enrollment queue, admin API, Stripe webhook. Routing metadata only.
3. **Durable Objects.** Tenant DO (cards, groups, ACLs, binding and revocation lists, seat limit, settings, rate limit), Device DO (hibernating socket, presence), Task DO (state machine, deadlines, metadata audit, ciphertext only when retained).
4. **D1 and R2.** D1: tenants, Stripe mapping, no content. R2: encrypted files only.
5. **Admin page.** Metadata and pending-approval queue; it never shows content.
6. **Reference bot template.** Tool-less reviewer.
7. **Release and distribution (no app-store or signing-vendor dependency).** The daemon is a command-line program distributed through GitHub releases, a Homebrew tap, a Linux package repo, `go install` and source builds. Releases and updates are signed with the project's own key (Ed25519 or minisign), which the daemon pins. Builds are reproducible, with published checksums and an SBOM. macOS and Linux need no vendor account (verify on a fresh Mac early). Windows: published hashes for IT allowlisting, source builds that enterprises can re-sign with their own certificate, and an optional project certificate later, as a convenience rather than a dependency.

## 3. Cryptography and key trust

**Rules.** Vetted libraries only (HPKE via the Go standard library or CIRCL, verify availability; libsodium acceptable). No custom primitives. One small crypto module with published test vectors. One fixed suite, no runtime negotiation (no downgrade).

**Tenant signing root.**
- Created by the first admin's daemon (`parley admin init`): an Ed25519 root key held in that daemon's keychain, with a recovery code and an encrypted backup. A second root holder can be added.
- The root signs, per device, a binding `{tenant, owner identity (user email or named service owner), device id, signing public key, version, not_after (90 days)}`. Encryption keys are one-time prekeys (below), not part of the binding.
- Daemons pin only the root public key. The admin shares the install command, which carries the root fingerprint, through a channel other than our service (chat or email), so the gateway cannot substitute it.
- **Enrollment.** The user signs in with SSO and the device generates its keys and requests approval. The admin's daemon lists pending devices (user, device name, fingerprint) and signs on confirm, with a batch option. Pods use the admin-minted single-use token, and the admin's daemon signs the binding. Optional "auto-approve" is off by default and labeled "trusts the gateway for new enrollments".
- **Versions.** Daemons reject any binding with a lower version than the one they have seen. Rotating the signing key means re-approval with a higher version. There is no long-term encryption key to rotate, because task encryption uses one-time prekeys.
- **Revocation.** A root-signed, versioned, timestamped revocation list, refreshed by the root holder's daemon at least weekly (an always-on admin daemon does this automatically). Daemons warn when the list is older than 7 days and refuse to send beyond 14 days.

**Sending a task.** The caller generates a fresh reply keypair `(rsk, rpk)` and a random 128-bit task id (never derived from content). It requests a one-time prekey from the target (below) and seals `inner` to it with HPKE base mode (X25519, HKDF-SHA256, ChaCha20-Poly1305), with `info` and `aad` set to the hash of the header fields (everything in the transcript below except the ciphertext hash). The signature covers the header and the ciphertext hash. `inner` holds the plaintext, `rpk`, the next-key for follow-ups, file keys and padding.

**Signed transcript (deterministic encoding), signed with the sender's Ed25519 key for every message in both directions:** protocol label and suite id, tenant id, sender device id, key id and binding version, target device id and prekey id, task id, context id, message sequence number, message type (TASK, STATUS, INPUT_REQUIRED, RESULT, ERROR, CANCEL), issued-at, expiry, SHA-256 of the encapsulated key and ciphertext, `rpk`, and the hash of the previous message in the task. For a TASK message the prekey id and its signed prekey object are part of the header.

**Replies** (results, status, questions, errors, cancel) reuse the same construction toward `rpk`, with a fresh HPKE context per message, the original task's hash, and an incrementing sequence number. The receiver treats the gateway's plaintext state code as a hint; the authoritative state is the one inside the signed message.

**On-demand one-time prekeys (forward secrecy).**
- To send a task, the caller's daemon asks the target daemon, over the live relay, for a prekey. The target checks the caller itself (root-signed binding, owner allowlist, per-caller rate limit), generates a fresh X25519 keypair, and returns the public half signed with its signing key over `{label, suite id, tenant id, device id, signing key id, binding version, prekey id, public key, caller device id, request nonce, created_at, expires_at}`. `expires_at` is the task expiry plus clock skew (default 15 min, max 24 h). The gateway only relays; it hands out nothing, so it cannot reuse, withhold selectively or forge prekeys.
- The caller verifies the signature, nonce and binding, then seals the task to that prekey.
- **Private prekeys live in memory only** (locked memory, no core dumps, zeroed on use, never written to disk, keychain or backups). A restart loses them, and any task in flight fails and is resent with a fresh prekey.
- **Receive order, at-most-once:** AEAD open, then signature and allowlist checks, then erase the private key, then acknowledge, then execute. Keys are erased only after a successful AEAD open, so junk frames cannot burn them. Consumed prekey ids are tombstoned until they expire, and redelivered frames for an acknowledged id are dropped. A crash after erasure means the task fails and the caller resends; plaintext is never persisted to survive a crash.
- **Follow-ups and replies.** Every message carries a fresh next-key for the peer inside `inner`; the peer erases the previous key on receipt. Reply keys are in memory only, live no longer than the task expiry, and are erased on CANCEL or FAILED, before any late reply is accepted.
- **Offline target.** The caller's daemon holds the pending task in memory, shows "waiting for recipient", watches the target's presence, and requests a prekey when it comes online, up to the task expiry. Nothing is stored at the gateway while waiting. If the caller restarts, the pending task fails.
- **Erasure on each OS.** Hold raw 32-byte scalars outside the Go heap in locked memory (mlock on macOS and Linux, VirtualLock on Windows) and zero them on use. Disable core dumps (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, `GOTRACEBACK=none`), use the hardened runtime without `get-task-allow` on macOS, and exclude the process from Windows crash dumps. Go's key objects offer no zeroing guarantee, so erasure is best effort and the docs say so.

**Authentication is by signature, not by Diffie-Hellman**, which avoids key-compromise impersonation and reflection (direction and both device ids are signed).

**Replay.** Each daemon keeps its own replay table keyed by `(sender device, task id, sequence)`, pruned at expiry. It never relies on the gateway's nonce.

**Padding.** Plaintext is padded inside the AEAD to power-of-two buckets, minimum 4 KiB. Files use fixed-size chunks.

**Files.** Per-file random key, chunked AEAD with counter nonces and a final-chunk flag; the file hash and key travel inside `inner`. Ciphertext goes to R2 under random keys through the Worker.

**Key loss or expiry.** If the device restarts and loses its in-memory prekeys, or a prekey expires before use, the task fails with "recipient key unavailable, resend". No admin recovery exists for content because no one but the device holds keys.

## 4. Retention modes (tenant setting)
- **Task delivery (both modes).** The gateway forwards task frames between live sockets and does not store them. An offline target is handled by the sender's daemon waiting (section 3), not by gateway queueing.
- **Strict (pass-through).** Results and status messages are also relayed only while the caller is connected and are stored nowhere. If the caller is disconnected, the task fails ("caller disconnected"). Best for pods and always-on bots. We say "not stored by our application", not "never persisted anywhere", because the platform may buffer in transit.
- **Queued (default).** Result and status ciphertext is stored until the caller acknowledges it, with a TTL (default 1 h, configurable 15 min to 24 h), then deleted, so a caller that briefly disconnects still gets its result. Content is unreadable to us throughout.
- **Both modes.** Metadata is kept 90 days (configurable) with a "ciphertext deleted at time X" record.
- **Daemon.** Payloads stay in memory. Each run gets a temp directory (mode 0700) deleted on completion. The local log is metadata only. The daemon turns off CLI history and transcripts where the CLI allows it, and `parley doctor` shows a red warning for each bot that retains data. Cards carry a self-declared, unenforced retention label.
- **Logging.** `invocation_logs` off, minimal sampling, no task or user ids in URLs (identifiers travel in WebSocket frames and bodies), and a redacting wrapper that allows ids, states, sizes and timestamps only. A build test fails if a payload field reaches a log call.

## 5. A2A interoperability
Discovery and task lifecycle use A2A v1.0 (card at the well-known path, `TASK_STATE_*` states including INPUT_REQUIRED, list, cancel, subscribe; push notifications unsupported). Message parts are opaque ciphertext parts. A standard third-party A2A client can reach the transport but cannot read content; content requires our daemon or SDK. CI jobs use a headless enrolled device. We claim "A2A v1.0 transport and lifecycle with encrypted message parts", not content interoperability.

## 6. End-to-end journeys
**A. Admin onboarding (~15 min).** Sign up, connect Google, Microsoft or Okta, run `parley admin init` (root key plus recovery code), add users and groups, choose retention mode, subscribe or stay free (3 devices), share the install command with its root fingerprint.
**B. Employee enrollment.** Install through Homebrew, the package repo or the install script (checksum and signature verified against the published release key), then `parley login --root <fingerprint>`, SSO, the browser shows a code and device name, keys are generated, the request waits for admin approval (batch approval is one click on the admin's daemon). Background service starts on boot. `parley test` sends a task to your own bot to prove the full path.
**C. Publish a bot.** Name, description, tags, examples (secrets lint), visibility or allowed groups, owner allowlist, approval mode, concurrency, timeout. Several bots per daemon.
**D. Discover and call.** The caller's bot uses the daemon's MCP tools or CLI: `find_agents`, `send_task`, `get_task(wait_seconds)`, `cancel_task`, `list_tasks`. The daemon verifies the target's root-signed binding and revocation status before sending, and asks the target for a one-time prekey over the live relay. Users see no key prompts. Results are marked untrusted.
**E. Long tasks.** SUBMITTED, WORKING (encrypted status text), INPUT_REQUIRED (encrypted question; reply on the same task), COMPLETED, FAILED, CANCELED, REJECTED.
**F. Not-happy paths.** Offline target (the caller's daemon waits up to the task expiry, then FAILED), busy (queue 5 then REJECTED), not permitted (REJECTED, bot hidden), timeout, recipient restarted and lost its keys (resend), caller disconnected (Strict), revocation list too old.
**G. Approval.** `none` for tool-less skills; `owner` for tool-using skills via `parley approve <id>`; no answer in 5 min means REJECTED.
**H. Pods.** Admin-minted single-use token, headless device, named service owner, binding signed by the admin's daemon; ideal for Strict.
**I. Offboarding.** Deactivation cascades: the root-signed revocation list is updated, sockets close, tasks are canceled, bots hidden. Sessions re-validate against the IdP every 24 h (72 h grace if the IdP is down).
**J. Updates.** Auto-update verified against the project's own pinned release key, with a pin-to-version option; protocol version in the handshake.
**K. Billing.** Stripe Checkout and Portal; seat limit enforced only at enrollment; live tunnels are never cut.
**L. Owner and security-team views.** Per-bot call log (metadata), admin kill-switch with a reason, metadata audit CSV, tenant export and deletion.

## 7. Threat table
| Threat | Control |
|---|---|
| Gateway, staff or account breach reads content | E2E encryption; no content keys server-side; canary test. |
| Malicious gateway substitutes keys | Tenant signing root, pinned root fingerprint distributed out of band, binding versions, signed revocation list. |
| Forged, tampered, reordered or swapped messages | Signed full transcript on every message in both directions; authoritative state inside signed messages. |
| Replay and reflection | Local replay table, expiry, direction and both device ids signed. |
| Stolen or lost device | Keychain storage for the signing key, short-lived connect token, IdP re-validation, signed revocation. In-memory one-time prekeys mean processed tasks cannot be decrypted; the thief gets only what is stored on the device and any unexpired unused prekey. |
| Prekey abuse (drain, reuse, fake, withhold) | The target device itself checks binding, allowlist and per-caller rate limits; the gateway hands out nothing; prekeys are signed and bound to the caller and a nonce; the device erases a key on first successful use, so reuse fails. |
| Unauthorized caller | Gateway visibility (advisory) plus the target daemon's identity allowlist from the binding. |
| Injection via task or result | Tool-less skills by default; tool-using skills need approval and are labeled until a sandbox is proven; results marked untrusted. |
| Compromised local bot using the caller interface | OS-user socket, sandbox blocks it, rate limits, optional confirm-outbound mode. Residual: a bot running as the user can send as the user. |
| Abuse and loops | Rate-limit counter in the Tenant DO, concurrency caps, delegation depth 3, timeouts. |
| Cross-tenant leakage | One Tenant DO per customer; tenant id in every Device and Task DO name. |
| Accidental plaintext copies | Logging rules in section 4, canary test, secrets lint on cards. |
| Supply chain | Release and update signatures from the project's own pinned key, reproducible builds, checksums, SBOM, minimal dependencies. |

## 8. Build order, spikes and gates
The build is delivered in phases, each with a demoable deliverable, a functional acceptance suite and coverage gates. See `delivery-and-test-plan.md`: Phase 0 foundation and release pipeline, Phase 1 tunnel and identity, Phase 2 secure messaging core, Phase 3 tasks and discovery, Phase 4 caller interface and adapters, Phase 5 product shell, Phase 6 hardening and pilot. The spikes below are folded into those phases as acceptance tests (spikes 1 and 2 in Phase 1, 3 and 4 in Phase 2, 5 and 6 in Phase 3, 7 and 9 in Phase 4, 8 in Phase 1).

Spikes (pass criteria)
1. Hibernation tunnel with a forced deploy and 20 reconnects: no lost or duplicated events.
2. Root and enrollment: admin approval flow, binding versions, rollback rejected, revocation list refresh and staleness behavior, recovery code restores the root.
3. Crypto: transcript test vectors, parser fuzzing, and a malicious-gateway harness that substitutes keys, replays, reorders, swaps replies and drops cancel messages. Every attack is rejected or detected. Prekeys: a crash between open and acknowledgment, and between erase and execute, ends in a clean failure and a successful resend; a prekey expiring while the sender waits is refused; junk frames cannot burn keys; a redelivered frame is dropped; a prekey request flood is rate-limited; a five-message follow-up chain erases each key; a late reply after CANCEL is rejected; a disk clone or restored backup holds no usable keys; and core-dump and swap scans find no key bytes.
4. Canary test: unique canary strings in input, result, status, question, error and file name; scan Durable Object storage, R2, D1, logs, URLs, headers and error messages. Pass = zero hits.
5. Retention: Strict stores nothing; Queued deletes at acknowledgment and TTL; restore a Durable Object from a recovery bookmark to confirm what Cloudflare retains; verify R2 deletion behavior.
6. Transport: the official A2A SDK transport completes a lifecycle with opaque encrypted parts (fall back to a thin custom transport if it assumes readable parts).
7. Adapters with hostile input; the sandbox cannot reach the local socket.
8. Login and groups: Google and Entra first.
9. Walking skeleton: two machines, a real MCP client finds and calls a bot end to end, including offline, cancel, expiry and INPUT_REQUIRED.
Gate: spikes 2, 3, 4 and 9 must pass before Phase 5 (product shell) begins.

## 9. Deferred, and what users get instead
Token streaming (encrypted status text instead). Gateway-side queueing of tasks for offline bots (the sender's daemon waits and retries instead). SCIM and IdP groups (admin-managed groups). Semantic search (name, description and tag filter). Gateway-side content DLP (impossible with E2E; daemon-side hooks later). MDM policy files. A real sandbox for tool-using skills (approval-gated and labeled until proven; unsupported on Windows). Cross-device bot sync (a bot is bound to one device).

## 10. Compliance and operations
Tenant export and deletion, subprocessor list (Cloudflare, Stripe), data-processing terms, no operator access to content. Counsel reviews every data-handling claim, including the wording in section 1.

## 11. Open decisions
- Admin approval friction for new devices (default: manual batch approval) versus the labeled auto-approve option.
- Queued default TTL (1 h proposed).
