# Parley: Tasks (MVP)

Phased delivery with acceptance tests. Requirements are in [spec.md](spec.md); architecture, testing strategy, coverage tiers and local-first development are in [plan.md](plan.md).

Every phase ends with something you can run and demonstrate, a functional acceptance suite that passes, and coverage gates that hold. The spikes in plan.md are folded into the phases.

Estimates are my judgment, not verified. Including the testing discipline, expect roughly 15 to 19 weeks to a pilot-ready release for one experienced developer working with AI coding agents. The secure messaging libraries are done at the end of Phase 2 (about weeks 6 to 8); the first encrypted two-machine echo is milestone M1 (after T414), which runs in parallel with Phase 3.

Revised 2026-11-04: daemon assembly is now explicit (T410 to T415), and the first end-to-end echo moves to milestone M1 after T414.

Task ids: `T<phase><nn>`. Tests derive from the journeys A to L in spec.md and are tracked in `tests/journeys.md` (journey, test id, phase).

## Phase 0: Foundation (about 1 week)

Deliverable: repository, CI on three OSes, local harness that boots a gateway and N daemons, own-key release pipeline, log-redaction wrapper, canary test scaffold.

- [x] T001 Repository layout (`parleyd`, `parley-cli`, gateway, admin page, tests), license headers, contribution docs
- [x] T002 CI on macOS, Linux and Windows
- [x] T003 Local harness: one command boots the gateway, a mock OIDC server and N daemons (see plan.md, Local-first development)
- [x] T004 Own-key release pipeline: reproducible builds, checksums, SBOM, minisign/Ed25519 signing
- [x] T005 Log-redaction wrapper (ids, states, sizes, timestamps only) with a build test that fails on a leaked payload field
- [x] T006 Canary test scaffold
- [x] T007 `tests/journeys.md` journey matrix
- [x] T008 Acceptance: harness boots; a release build is reproducible and verifiable with the project key; the redaction build test fails on a leaked payload field

## Phase 1: Tunnel and identity (about 3 weeks)

Deliverable: two daemons enroll under an admin root and show online; revocation works. Spikes 1, 2 and 8.

- [x] T101 WSS to Device DO with hibernation, reconnect and resume
- [x] T102 OIDC login (Google and Entra) with a mock IdP for tests
- [x] T103 `parley-cli admin init`: root key and recovery code
- [x] T104 Enrollment tokens and the approval queue
- [x] T105 Root-signed device bindings with versions and not_after
- [x] T106 Signed revocation list with refresh, staleness warning and send refusal
- [x] T107 Acceptance: enroll, approve and revoke; binding rollback rejected; recovery code restores the root; stale revocation list behavior
- [x] T108 Acceptance: 20 forced reconnects and a deploy during a 10k-message soak lose or duplicate nothing
- [ ] T109 Real-Cloudflare reality check 1: limits, costs, hibernation timing, deploy-driven disconnects, real Google and Entra logins
  - [x] Cloudflare: limits, costs, hibernation timing and what a real deploy does to live sockets, measured on 2026-11-02 ([reality-check-1.md](reality-check-1.md))
  - [x] Cloudflare: the 10k soak against the real Worker and real client, 17 closes and 3 real deploys under traffic: `rx_seq` 10,000, 0 missing, 0 duplicated, 190 lost events retried, 302 frames retransmitted ([reality-check-1.md](reality-check-1.md)). Deploys did not disconnect or visibly re-instantiate anything
  - Entra real-tenant check: not possible while no free Entra tenant is available (the free tier was removed); covered by T111 simulator conformance. Residual risk: real-Entra quirks (consent screens, admin consent, claim overage, tenant-specific issuer details) are unverified until a real tenant is available, e.g. a design-partner tenant during the pilot. Google real login passed (personal and Workspace); hosted-domain enforcement run still open.
- [x] T110 Gates: tier 1 at 100%, tier 2 gates met
- [ ] T111 Entra simulator: an Entra-shaped profile for the local mock IdP (tests/harness/oidc.mjs) with fixtures and gateway conformance tests: v2.0 discovery and issuer format with the tenant id, tid and oid claims, preferred_username without or with unverified email, wrong-tenant and multi-tenant (common/organizations) issuers, key rotation (kid miss then refetch), expired and wrong-audience tokens, replayed code, claim overage; fixtures taken from Microsoft's published claims reference and recorded with their source, cross-checked against one independent open-source mock OIDC server in an optional CI job so we do not only test against our own assumptions; used by gateway tests now and by the dashboard identity-provider setup step later

## Phase 2: Secure messaging core (about 2 to 3 weeks)

Deliverable: the secure messaging libraries are complete and attack-tested (T201 to T210). The `parley-cli test` end-to-end encrypted echo between two machines is delivered by T414 in Phase 4 (milestone M1). Spikes 3 and 4.

- [x] T201 HPKE plus signed transcripts, with published test vectors
- [x] T202 On-demand prekeys (in-memory, locked, zeroed on use)
- [x] T203 Local replay table
- [x] T204 Receive order: open, verify, erase, ack, execute
- [x] T205 Padding to power-of-two buckets and client-side encrypted files
- [x] T206 Malicious-gateway harness (key substitution, replay, reorder, drop, swapped replies, withheld and reused prekeys)
- [x] T207 Acceptance: test vectors pass; fuzzing finds no crashes; every attack is rejected or detected
- [x] T208 Acceptance: crash points (between open and ack, between erase and execute) end in a clean fail and resend; junk frames cannot burn keys
- [x] T209 Acceptance: core-dump and swap scans find no key bytes; canary test finds zero hits in all storage
- [x] T210 Gates: tier 1 at 100% with mutation testing

## Phase 3: Tasks and discovery (about 2 to 3 weeks)

Deliverable: `send_task` and `get_task` between two machines with an API-backed tool-less bot. Spikes 5 and 6.

- [x] T301 Task DO state machine, deadlines, cancel, expiry
- [x] T302 A2A v1.0 transport with encrypted parts, status and INPUT_REQUIRED
- [x] T303 Directory, groups and ACLs
- [x] T304 Retention modes (Strict and Queued), TTL deletion
- [x] T305 Rate limits; sender-side waiting for offline targets
- [ ] T310 Device connect tokens: short-lived, bound to tenant and device, issued after enrollment; the Worker accepts them on `/v1/connect` and `/a2a` (both are closed until then). Restores the parked acceptance tests listed in `tests/pending-t310.test.mjs` and `internal/tunnel/pending_test.go`
- [ ] T306 Acceptance: exhaustive state-machine tests; the official A2A SDK completes a lifecycle
- [ ] T307 Acceptance: ACL matrix; retention deletion at acknowledgment and TTL
- [ ] T308 Acceptance: recovery-bookmark test documents what Cloudflare retains; R2 deletion behavior verified
- [ ] T309 Real-Cloudflare reality check 2

## Phase 4: Daemon assembly, caller interface and adapters (about 3 to 4 weeks)

Deliverable: a real MCP client (Claude Code) finds and calls a bot across two machines, including offline, cancel, expiry and INPUT_REQUIRED. Spikes 7 and 9.

Milestone M1 (after T414): `parley-cli test` sends an encrypted echo between two local daemons through a local gateway. It is the first thing to run by hand. T410 to T415 do not depend on T304 or T305, so they run in parallel with the rest of Phase 3.

- [ ] T410 Daemon core: `parleyd` lifecycle and config, device signing key in the OS keychain, OS-user-restricted local socket, graceful shutdown, redacted logging, and a supervisor for the tunnel client, revocation refresh and binding store
- [ ] T415 Device connect tokens: a device proves possession of its bound key (signed challenge) and receives a short-lived connect token; /v1/connect verifies it, rejects revoked, expired and unbound devices and replayed challenges, and the parked tunnel and canary integration tests (named pending tests left by the DEV_AUTH removal) are restored needs: T410
- [ ] T411 Enrollment from the daemon: `parley-cli login` and `enroll` (sign-in, request, wait for approval, store the binding), resumable after a restart needs: T410, T415
- [ ] T412 Message pipeline wired up: inbound tunnel event, verify, open, erase, ack and hand to the bot (internal/receive); outbound prekey request, seal, send and status handling needs: T410, T415
- [ ] T413 Bot interface and a fake bot: the adapter contract that T402 implements, with contract tests against the fake needs: T412
- [ ] T414 `parley-cli test`: encrypted echo between two daemons through a local gateway (milestone M1) needs: T411, T412, T413, T415
- [ ] T401 MCP server and CLI over the restricted local socket needs: T410, T412
- [ ] T402 API and CLI adapters, adapter contract tests with a fake bot needs: T413
- [ ] T403 Approval flow (`parley-cli approve`)
- [ ] T404 Hostile-input tests
- [ ] T405 Acceptance: the walking-skeleton journey passes on macOS and Linux
- [ ] T406 Acceptance: sandboxed bots cannot reach the local socket; hostile inputs stay within limits

## Phase 5: Product shell (about 3 to 4 weeks)

Deliverable: pilot-ready build. Gate to start: spikes 2, 3, 4 and 9 have passed.

- [ ] T501 Admin page (metadata only)
  - ~~**RELEASE BLOCKER:** real admin/user session auth must replace the `DEV_AUTH` placeholder identity.~~ Done by dashboard task T001 (gateway admin sessions; `DEV_AUTH` removed). `scripts/check-dev-auth.mjs` is the release gate (run by the Release workflow and `tests/dev-auth-gate.test.mjs`).
- [ ] T502 Stripe billing in test mode with seat enforcement at enrollment, 7-day grace
- [ ] T503 Offboarding cascade, audit CSV, tenant export and deletion
- [ ] T504 Auto-update from the pinned project key; distribution channels (GitHub releases, Homebrew tap, Linux package repo, `go install`, source)
- [ ] T505 Windows daemon
- [ ] T506 ACP adapter
- [ ] T507 Approval-gated tool-using skills; reference tool-less reviewer bot
- [ ] T508 Docs and hardening guide
- [ ] T509 Acceptance: all journeys A to L pass end to end on all three OSes
- [ ] T510 Acceptance: billing webhooks tested against Stripe test events
- [ ] T511 Acceptance: install via each channel verified on fresh machines, including a fresh Mac with no Apple account

## Phase 6: Hardening and pilot (about 2 weeks, partly parallel)

Deliverable: design-partner pilot.

- [ ] T601 Independent crypto and penetration review
- [ ] T602 Load and chaos runs (forced deploys, reconnect storms, killed daemons, clock skew)
- [ ] T603 Claims review with counsel
- [ ] T604 Fix findings
- [ ] T605 Acceptance: no open high-severity findings; soak run clean

## Per-phase exit checklist

- [ ] Acceptance suite green on all three OSes
- [ ] Coverage gates met for every tier touched
- [ ] Canary and redaction tests green
- [ ] Journey matrix updated
- [ ] Demo recorded or scripted so you can reproduce it

## Journey to phase matrix

| Journey | Phase |
|---|---|
| A Admin onboarding, B Employee enrollment | 1, 5 |
| C Publish a bot, D Discover and call, E Long tasks, F Not-happy paths | 3, 4 |
| G Approval | 4, 5 |
| H Pods, I Offboarding, J Updates, K Billing, L Owner and security views | 5 |
