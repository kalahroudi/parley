# Parley: Plan (MVP)

How Parley is built. The requirements it satisfies are in [spec.md](spec.md); the phased work and acceptance tests are in [tasks.md](tasks.md).

## Decisions

Cloudflare only (Workers, three Durable Object classes, D1, R2). Daemon = connector and gatekeeper; bots are whatever the customer brings (API, headless CLI, ACP adapters). Vendor terms are the customer's responsibility, with a notice. Flat per-device seats via Stripe, enforced only at enrollment. Open source, with no dependency on any app store or platform signing vendor.

## Components

1. **Daemon `parleyd` and CLI `parley-cli` (Go; macOS, Linux, Windows).** `parleyd` is the background service: outbound WSS only, 1..n bots, verification of bindings, signatures and envelopes, owner policy, adapters, crypto module, local MCP server, local replay table. `parley-cli` is the user-facing command (login, test, doctor, approve, admin init, find and send) and talks to `parleyd` over an OS-user-restricted local socket.
2. **Gateway Worker (TypeScript).** A2A v1.0 transport and lifecycle, OIDC login (Google, Microsoft Entra, generic OIDC), enrollment queue, admin API, Stripe webhook. Routing metadata only.
3. **Durable Objects.** Tenant DO (cards, groups, ACLs, binding and revocation lists, seat limit, settings, rate limit), Device DO (hibernating socket, presence), Task DO (state machine, deadlines, metadata audit, ciphertext only when retained).
4. **D1 and R2.** D1: tenants, Stripe mapping, no content. R2: encrypted files only.
5. **Admin page.** Metadata and pending-approval queue; it never shows content.
6. **Reference bot template.** Tool-less reviewer.
7. **Release and distribution (no app-store or signing-vendor dependency).** The daemon is a command-line program distributed through GitHub releases, a Homebrew tap, a Linux package repo, `go install` and source builds. Releases and updates are signed with the project's own key (Ed25519 or minisign), which the daemon pins. Builds are reproducible, with published checksums and an SBOM. macOS and Linux need no vendor account (verify on a fresh Mac early). Windows: published hashes for IT allowlisting, source builds that enterprises can re-sign with their own certificate, and an optional project certificate later, as a convenience rather than a dependency.


## Cryptography and key trust

**Rules.** Vetted libraries only (HPKE via the Go standard library or CIRCL, verify availability; libsodium acceptable). No custom primitives. One small crypto module with published test vectors. One fixed suite, no runtime negotiation (no downgrade).

**Tenant signing root.**
- Created by the first admin's daemon (`parley-cli admin init`): an Ed25519 root key held in that daemon's keychain, with a recovery code and an encrypted backup. A second root holder can be added.
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


## Retention modes (tenant setting)

- **Task delivery (both modes).** The gateway forwards task frames between live sockets and does not store them. An offline target is handled by the sender's daemon waiting (see "Cryptography and key trust"), not by gateway queueing.
- **Strict (pass-through).** Results and status messages are also relayed only while the caller is connected and are stored nowhere. If the caller is disconnected, the task fails ("caller disconnected"). Best for pods and always-on bots. We say "not stored by our application", not "never persisted anywhere", because the platform may buffer in transit.
- **Queued (default).** Result and status ciphertext is stored until the caller acknowledges it, with a TTL (default 1 h, configurable 15 min to 24 h), then deleted, so a caller that briefly disconnects still gets its result. Content is unreadable to us throughout.
- **Both modes.** Metadata is kept 90 days (configurable) with a "ciphertext deleted at time X" record.
- **Daemon.** Payloads stay in memory. Each run gets a temp directory (mode 0700) deleted on completion. The local log is metadata only. The daemon turns off CLI history and transcripts where the CLI allows it, and `parley-cli doctor` shows a red warning for each bot that retains data. Cards carry a self-declared, unenforced retention label.
- **Logging.** `invocation_logs` off, minimal sampling, no task or user ids in URLs (identifiers travel in WebSocket frames and bodies), and a redacting wrapper that allows ids, states, sizes and timestamps only. A build test fails if a payload field reaches a log call.


## Threat model

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
| Accidental plaintext copies | Logging rules in "Retention modes", canary test, secrets lint on cards. |
| Supply chain | Release and update signatures from the project's own pinned key, reproducible builds, checksums, SBOM, minimal dependencies. |


## Spikes and gates

The spikes are delivered inside the phases in [tasks.md](tasks.md): spikes 1, 2 and 8 in Phase 1, spikes 3 and 4 in Phase 2, spikes 5 and 6 in Phase 3, and spikes 7 and 9 in Phase 4.

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


## Testing strategy

### Principles

- **Tests come from the journeys.** Each journey A to L in the design maps to at least one end-to-end test, tracked in `tests/journeys.md` (journey, test id, phase). A journey is done when its test passes.
- **CI runs on macOS, Linux and Windows** from Phase 0. Platform-specific code is tested on its own platform.
- **No phase exits** until its acceptance tests pass, its coverage gates hold, and the previous phases' tests still pass.
- **Test the attacker, not only the user.** Adversarial tests are first-class from Phase 2.


### Test layers

1. **Unit tests.** Go (`go test`, with the race detector) for the daemon; TypeScript for the gateway.
2. **Property and fuzz tests.** Go native fuzzing for transcript parsing, envelope decoding and framing; property tests for the task state machine.
3. **Workers integration tests.** Durable Object, alarm and hibernation behavior run inside the real Workers runtime (Vitest with the Cloudflare Workers pool; verify current coverage-provider support).
4. **End-to-end tests.** A local gateway plus several real daemons on separate processes or containers, driven through the CLI and MCP interface. These execute the journeys.
5. **Adversarial harness.** A malicious-gateway test double that substitutes keys, replays, reorders, drops, swaps replies, withholds and reuses prekeys.
6. **Conformance.** The official A2A SDK client against the transport.
7. **Security scans.** Canary test across all storage, logs, URLs and headers; core-dump and swap scans for key bytes; dependency audit; secrets scan.
8. **Soak and chaos.** Forced deploys, reconnect storms, killed daemons, clock skew, dropped connections.


### Coverage policy

"Full coverage" is enforced where it protects security, with numbers that fail the build elsewhere. 100% everywhere is not worth the cost (OS glue and unreachable defensive branches), and coverage alone doesn't prove correctness, so tier 1 also gets mutation testing.

| Tier | What | Gate |
|---|---|---|
| 1 | Crypto module, transcript encode/decode, envelope and signature verification, replay table, prekey lifecycle, binding and revocation verification, ACL evaluation, task state machine, deadlines and retention logic, log-redaction wrapper | 100% line and branch, plus mutation testing; no exclusions |
| 2 | Gateway handlers, Tenant/Device/Task DO logic, daemon core, adapters, caller interface | At least 95% line and 90% branch |
| 3 | Admin page, OS-specific glue (service install, keychain wrappers) | At least 85%, plus integration tests on each OS |

Every coverage exclusion needs a written reason in the code and review sign-off. CI fails if coverage in any tier drops.


## Local-first development

Almost everything runs on one machine, which also lets contributors work without a Cloudflare account.

- The gateway and Durable Objects run in Cloudflare's local runtime (`wrangler dev`), with local stand-ins for D1 and R2. Verify WebSocket hibernation behavior locally early.
- Several real daemons run as separate processes or containers, driven through the CLI and a real MCP client.
- A mock OIDC server stands in for Google and Entra. Stripe's test mode with its CLI forwards webhooks to the local gateway.
- One command (for example `make dev`) boots the gateway, a mock identity provider and N daemons.
- Two short reality checks on a real Cloudflare account, one in Phase 1 and one in Phase 3: real limits and costs, what Cloudflare retains after deletion (the recovery-bookmark test), R2 deletion behavior, real hibernation timing and deploy-driven disconnects, and real Google and Entra logins.
- macOS and Windows daemons must be tested on those systems, using CI runners or local VMs.

## Schedule risks

Signing-root approval UX, the A2A SDK possibly needing a custom transport for encrypted parts, and Windows service and key-handling quirks. Each has a test in an early phase so surprises come early.

## Design history: what changed from v3

1. End-to-end encryption is mandatory and always on, using HPKE plus signed transcripts (see "Cryptography and key trust").
2. A tenant signing root is in the MVP, so even a malicious gateway cannot substitute device keys. Trust-on-first-use is removed.
3. Two retention modes: Strict (pass-through, no buffering) and Queued (short-lived ciphertext).
4. Every caller is a device with keys. Keyless personal tokens are dropped.
5. Claims are reworded to what we can honestly prove (see spec.md, "Guarantees and non-guarantees").
6. Forward secrecy through on-demand one-time prekeys is in the MVP: tasks already processed stay unreadable even if a device is stolen later.
7. Offline targets: the sender's daemon waits and retries; the gateway never queues task ciphertext. (A prekey pool at the gateway was rejected after review: more attack surface and no real benefit.)

