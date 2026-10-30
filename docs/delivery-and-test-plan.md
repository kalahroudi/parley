# Parley: Phased Delivery and Test Plan

Companion to `design.md`. Every phase ends with something you can run and demonstrate, a functional acceptance suite that passes, and coverage gates that hold. The spikes in the design are folded into the phases.

Estimates are my judgment, not verified. Including the testing discipline below, expect roughly 15 to 19 weeks to a pilot-ready release for one experienced developer working with AI coding agents. The first encrypted two-machine demo lands at the end of Phase 2 (about weeks 6 to 8).

## 1. Principles
- **Tests come from the journeys.** Each journey A to L in the design maps to at least one end-to-end test, tracked in `tests/journeys.md` (journey, test id, phase). A journey is done when its test passes.
- **CI runs on macOS, Linux and Windows** from Phase 0. Platform-specific code is tested on its own platform.
- **No phase exits** until its acceptance tests pass, its coverage gates hold, and the previous phases' tests still pass.
- **Test the attacker, not only the user.** Adversarial tests are first-class from Phase 2.

## 2. Test layers
1. **Unit tests.** Go (`go test`, with the race detector) for the daemon; TypeScript for the gateway.
2. **Property and fuzz tests.** Go native fuzzing for transcript parsing, envelope decoding and framing; property tests for the task state machine.
3. **Workers integration tests.** Durable Object, alarm and hibernation behavior run inside the real Workers runtime (Vitest with the Cloudflare Workers pool; verify current coverage-provider support).
4. **End-to-end tests.** A local gateway plus several real daemons on separate processes or containers, driven through the CLI and MCP interface. These execute the journeys.
5. **Adversarial harness.** A malicious-gateway test double that substitutes keys, replays, reorders, drops, swaps replies, withholds and reuses prekeys.
6. **Conformance.** The official A2A SDK client against the transport.
7. **Security scans.** Canary test across all storage, logs, URLs and headers; core-dump and swap scans for key bytes; dependency audit; secrets scan.
8. **Soak and chaos.** Forced deploys, reconnect storms, killed daemons, clock skew, dropped connections.

## 3. Coverage policy
"Full coverage" is enforced where it protects security, with numbers that fail the build elsewhere. 100% everywhere is not worth the cost (OS glue and unreachable defensive branches), and coverage alone doesn't prove correctness, so tier 1 also gets mutation testing.

| Tier | What | Gate |
|---|---|---|
| 1 | Crypto module, transcript encode/decode, envelope and signature verification, replay table, prekey lifecycle, binding and revocation verification, ACL evaluation, task state machine, deadlines and retention logic, log-redaction wrapper | 100% line and branch, plus mutation testing; no exclusions |
| 2 | Gateway handlers, Tenant/Device/Task DO logic, daemon core, adapters, caller interface | At least 95% line and 90% branch |
| 3 | Admin page, OS-specific glue (service install, keychain wrappers) | At least 85%, plus integration tests on each OS |

Every coverage exclusion needs a written reason in the code and review sign-off. CI fails if coverage in any tier drops.

## 4. Phases

**Phase 0: Foundation (about 1 week)**
- Deliverable: repository, CI on three OSes, local test harness that boots a gateway and N daemons, own-key release pipeline (reproducible builds, checksums, SBOM), log-redaction wrapper, canary test scaffold.
- Acceptance: harness boots; a release build is reproducible and verifiable with the project key; redaction build-test fails on a leaked payload field.

**Phase 1: Tunnel and identity (about 3 weeks)**
- Deliverable: two daemons enroll under an admin root and show online; revocation works.
- Includes: WSS to Device DO with hibernation, reconnect and resume, OIDC login (Google and Entra), `admin init`, approval queue, bindings with versions, revocation list, enrollment tokens.
- Acceptance: enroll, approve, revoke; binding rollback rejected; recovery code restores the root; 20 forced reconnects and a deploy during a 10k-message soak lose or duplicate nothing; stale revocation list behavior.
- Gates: tier 1 at 100%, tier 2 gates met.

**Phase 2: Secure messaging core (about 2 to 3 weeks)**
- Deliverable: `parley test` sends an end-to-end encrypted echo between two machines.
- Includes: HPKE plus signed transcripts, on-demand prekeys, replay table, erase-then-ack order, padding, files.
- Acceptance: test vectors; fuzzing finds no crashes; every attack in the malicious-gateway harness is rejected or detected; crash points (between open and ack, between erase and execute) end in a clean fail and resend; junk frames cannot burn keys; core-dump and swap scans find no key bytes; canary test finds zero hits in all storage.
- Gates: tier 1 at 100% with mutation testing.

**Phase 3: Tasks and discovery (about 2 to 3 weeks)**
- Deliverable: `send_task` and `get_task` between two machines with an API-backed tool-less bot.
- Includes: Task DO state machine, A2A transport with encrypted parts, directory and ACLs, retention modes (Strict and Queued), status, INPUT_REQUIRED, cancel, expiry, rate limits, sender-side waiting for offline targets.
- Acceptance: exhaustive state-machine tests; the official A2A SDK completes a lifecycle; ACL matrix; retention deletion at acknowledgment and TTL; recovery-bookmark test documents what Cloudflare retains; R2 deletion behavior verified.

**Phase 4: Caller interface and adapters (about 2 to 3 weeks)**
- Deliverable: a real MCP client (Claude Code) finds and calls a bot across two machines, including offline, cancel, expiry and INPUT_REQUIRED.
- Includes: MCP server and CLI over the restricted local socket, API and CLI adapters, adapter contract tests with a fake bot, approval flow, hostile-input tests.
- Acceptance: the walking-skeleton journey passes on macOS and Linux; sandboxed bots cannot reach the local socket; hostile inputs stay within limits.

**Phase 5: Product shell (about 3 to 4 weeks)**
- Deliverable: pilot-ready build.
- Includes: admin page, Stripe billing in test mode with seat enforcement, offboarding cascade, audit CSV, tenant export and deletion, auto-update from the pinned project key, distribution channels, Windows daemon, ACP adapter, approval-gated tool-using skills, docs and hardening guide.
- Acceptance: all journeys A to L pass end to end on all three OSes; billing webhooks tested against Stripe test events; install via each channel verified on fresh machines (including a fresh Mac with no Apple account).

**Phase 6: Hardening and pilot (about 2 weeks, partly parallel)**
- Deliverable: design-partner pilot.
- Includes: independent crypto and penetration review, load and chaos runs, claims review with counsel, fixes.
- Acceptance: no open high-severity findings; soak run clean.

## 5. Per-phase exit checklist
1. Acceptance suite green on all three OSes.
2. Coverage gates met for every tier touched.
3. Canary and redaction tests green.
4. Journey matrix updated.
5. Demo recorded or scripted so you can reproduce it.

## 6. Risks to the schedule
Signing-root approval UX, the A2A SDK possibly needing a custom transport for encrypted parts, and Windows service and key-handling quirks. Each has a test in an early phase so surprises come early.
