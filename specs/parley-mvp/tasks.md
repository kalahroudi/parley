# Parley: Tasks (MVP)

Phased delivery with acceptance tests. Requirements are in [spec.md](spec.md); architecture, testing strategy, coverage tiers and local-first development are in [plan.md](plan.md).

Every phase ends with something you can run and demonstrate, a functional acceptance suite that passes, and coverage gates that hold. The spikes in plan.md are folded into the phases.

Estimates are my judgment, not verified. Including the testing discipline, expect roughly 15 to 19 weeks to a pilot-ready release for one experienced developer working with AI coding agents. The first encrypted two-machine demo lands at the end of Phase 2 (about weeks 6 to 8).

Task ids: `T<phase><nn>`. Tests derive from the journeys A to L in spec.md and are tracked in `tests/journeys.md` (journey, test id, phase).

## Phase 0: Foundation (about 1 week)

Deliverable: repository, CI on three OSes, local harness that boots a gateway and N daemons, own-key release pipeline, log-redaction wrapper, canary test scaffold.

- [ ] T001 Repository layout (`parleyd`, `parley-cli`, gateway, admin page, tests), license headers, contribution docs
- [ ] T002 CI on macOS, Linux and Windows
- [ ] T003 Local harness: one command boots the gateway, a mock OIDC server and N daemons (see plan.md, Local-first development)
- [ ] T004 Own-key release pipeline: reproducible builds, checksums, SBOM, minisign/Ed25519 signing
- [ ] T005 Log-redaction wrapper (ids, states, sizes, timestamps only) with a build test that fails on a leaked payload field
- [ ] T006 Canary test scaffold
- [ ] T007 `tests/journeys.md` journey matrix
- [ ] T008 Acceptance: harness boots; a release build is reproducible and verifiable with the project key; the redaction build test fails on a leaked payload field

## Phase 1: Tunnel and identity (about 3 weeks)

Deliverable: two daemons enroll under an admin root and show online; revocation works. Spikes 1, 2 and 8.

- [ ] T101 WSS to Device DO with hibernation, reconnect and resume
- [ ] T102 OIDC login (Google and Entra) with a mock IdP for tests
- [ ] T103 `parley-cli admin init`: root key and recovery code
- [ ] T104 Enrollment tokens and the approval queue
- [ ] T105 Root-signed device bindings with versions and not_after
- [ ] T106 Signed revocation list with refresh, staleness warning and send refusal
- [ ] T107 Acceptance: enroll, approve and revoke; binding rollback rejected; recovery code restores the root; stale revocation list behavior
- [ ] T108 Acceptance: 20 forced reconnects and a deploy during a 10k-message soak lose or duplicate nothing
- [ ] T109 Real-Cloudflare reality check 1: limits, costs, hibernation timing, deploy-driven disconnects, real Google and Entra logins
- [ ] T110 Gates: tier 1 at 100%, tier 2 gates met

## Phase 2: Secure messaging core (about 2 to 3 weeks)

Deliverable: `parley-cli test` sends an end-to-end encrypted echo between two machines. Spikes 3 and 4.

- [ ] T201 HPKE plus signed transcripts, with published test vectors
- [ ] T202 On-demand prekeys (in-memory, locked, zeroed on use)
- [ ] T203 Local replay table
- [ ] T204 Receive order: open, verify, erase, ack, execute
- [ ] T205 Padding to power-of-two buckets and client-side encrypted files
- [ ] T206 Malicious-gateway harness (key substitution, replay, reorder, drop, swapped replies, withheld and reused prekeys)
- [ ] T207 Acceptance: test vectors pass; fuzzing finds no crashes; every attack is rejected or detected
- [ ] T208 Acceptance: crash points (between open and ack, between erase and execute) end in a clean fail and resend; junk frames cannot burn keys
- [ ] T209 Acceptance: core-dump and swap scans find no key bytes; canary test finds zero hits in all storage
- [ ] T210 Gates: tier 1 at 100% with mutation testing

## Phase 3: Tasks and discovery (about 2 to 3 weeks)

Deliverable: `send_task` and `get_task` between two machines with an API-backed tool-less bot. Spikes 5 and 6.

- [ ] T301 Task DO state machine, deadlines, cancel, expiry
- [ ] T302 A2A v1.0 transport with encrypted parts, status and INPUT_REQUIRED
- [ ] T303 Directory, groups and ACLs
- [ ] T304 Retention modes (Strict and Queued), TTL deletion
- [ ] T305 Rate limits; sender-side waiting for offline targets
- [ ] T306 Acceptance: exhaustive state-machine tests; the official A2A SDK completes a lifecycle
- [ ] T307 Acceptance: ACL matrix; retention deletion at acknowledgment and TTL
- [ ] T308 Acceptance: recovery-bookmark test documents what Cloudflare retains; R2 deletion behavior verified
- [ ] T309 Real-Cloudflare reality check 2

## Phase 4: Caller interface and adapters (about 2 to 3 weeks)

Deliverable: a real MCP client (Claude Code) finds and calls a bot across two machines, including offline, cancel, expiry and INPUT_REQUIRED. Spikes 7 and 9.

- [ ] T401 MCP server and CLI over the restricted local socket
- [ ] T402 API and CLI adapters, adapter contract tests with a fake bot
- [ ] T403 Approval flow (`parley-cli approve`)
- [ ] T404 Hostile-input tests
- [ ] T405 Acceptance: the walking-skeleton journey passes on macOS and Linux
- [ ] T406 Acceptance: sandboxed bots cannot reach the local socket; hostile inputs stay within limits

## Phase 5: Product shell (about 3 to 4 weeks)

Deliverable: pilot-ready build. Gate to start: spikes 2, 3, 4 and 9 have passed.

- [ ] T501 Admin page (metadata only)
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
