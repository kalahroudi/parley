# Journey matrix

Every journey A to L in [spec.md](../specs/parley-mvp/spec.md) maps to at least one end-to-end test. A journey is done when its tests pass. Phases follow the journey to phase matrix in [tasks.md](../specs/parley-mvp/tasks.md); `tests/journeys.test.mjs` fails if a journey is missing, an id repeats, or a phase disagrees with that matrix.

Status is `planned` until the test exists and passes, then `passing`. Update this file in the same change that adds or fixes a test. A test names its id (for example in its title) so the status check can find it. Phase 5 rows (T509) run on macOS, Linux and Windows; phase 4 rows (T405) run on macOS and Linux; earlier phases run on the CI matrix of all three.

| Journey | Test id | Phase | Status | Scenario |
|---|---|---|---|---|
| A Admin onboarding | JA-01 | 1 | passing | `admin init` creates the root key and recovery code; the recovery code restores the root (T107) |
| A Admin onboarding | JA-02 | 5 | planned | Sign-up, IdP connection, users and groups, retention mode, free tier of 3 devices, install command with root fingerprint |
| B Employee enrollment | JB-01 | 1 | planned | `login --root <fingerprint>`, SSO, admin approval, binding signed, device shows online; wrong fingerprint refused (T107) |
| B Employee enrollment | JB-02 | 5 | planned | Install from each channel with checksum and signature verified, service starts on boot, batch approval, `parley-cli test` succeeds |
| C Publish a bot | JC-01 | 3 | planned | Publish a card with visibility, groups and allowlist; the secrets lint rejects a secret; several bots on one daemon |
| D Discover and call | JD-01 | 3 | planned | `find_agents` and `send_task` / `get_task` between two daemons; binding and revocation verified before send |
| D Discover and call | JD-02 | 4 | passing | A real MCP client finds and calls a bot across two machines; results marked untrusted (T405) |
| E Long tasks | JE-01 | 3 | planned | Full lifecycle SUBMITTED, WORKING, COMPLETED with encrypted status text; FAILED, CANCELED, REJECTED terminals |
| E Long tasks | JE-02 | 4 | passing | INPUT_REQUIRED question and reply on the same task through the MCP client |
| F Not-happy paths | JF-01 | 3 | planned | Offline target (wait then FAILED at expiry), busy (queue 5 then REJECTED), not permitted (REJECTED, bot hidden), timeout |
| F Not-happy paths | JF-02 | 4 | planned | Recipient restart loses keys and resend succeeds; caller disconnected in Strict; revocation list too old refuses send |
| G Approval | JG-01 | 4 | planned | `none` runs tool-less skills; `owner` waits for `parley-cli approve <id>`; no answer in 5 min is REJECTED |
| G Approval | JG-02 | 5 | planned | Approval-gated tool-using skill is labeled and runs only after approval, with the reference reviewer bot |
| H Pods | JH-01 | 5 | planned | Single-use token enrolls a headless device under a named service owner; binding signed by the admin's daemon; token reuse fails |
| I Offboarding | JI-01 | 5 | planned | Deactivation updates the revocation list, closes sockets, cancels tasks, hides bots; IdP re-validation at 24 h with 72 h grace |
| J Updates | JJ-01 | 5 | planned | Auto-update accepts a release signed by the pinned key, rejects any other; pin-to-version holds; protocol version in handshake |
| K Billing | JK-01 | 5 | planned | Stripe test-mode Checkout and Portal; seat limit blocks only new enrollment; live tunnels are never cut |
| L Owner and security views | JL-01 | 5 | planned | Per-bot call log, admin kill-switch with reason, metadata audit CSV, tenant export and deletion; no content anywhere |

## T405 walking skeleton: last run and what it does not cover

`tests/walking-skeleton.test.mjs` runs in the CI `test` job on macOS and Linux (it skips itself on Windows, which has no pseudo-terminal for the approval steps) with real `parleyd` and `parley-cli mcp` processes, the real gateway (`wrangler dev`), and a bot behind the CLI adapter. Last run: passing on macOS (about 2 minutes). It covers enrollment and approval of three devices, discovery, an echo, INPUT_REQUIRED with an answer on the same task, cancel (the bot's process ends), a stranger refused by the target's own allowlist, an offline target delivered once on return, an expired task that never runs, a bot daemon restarted mid-task (the lost task is not run again; a resend works), a revoked target (`recipient_not_found`, nothing reaches the bot), owner approval on a real pseudo-terminal (`tests/harness/ptyrun`: the owner is shown the task and types a no, then a yes; a deny rejects the task and the bot never runs; no terminal means no answer; a bot the daemon started is refused when it tries to approve or deny, and a held task reaches the bot only after approval) and the canary scan of the gateway's storage and log and of every daemon's output. Removing the gateway's revocation filter, the daemon's refusal of bot callers, the approval gate, or leaking one reply's text into a daemon log, turns it red.

Not covered by this journey, and why:

- Admin init and the recovery code: JA-01 (`acceptance.test.mjs`); the journey's admin is the test itself, which holds the root key.
- Replay refused: the journey sends no replayed frame (that needs a gateway that replays), so removing the replay check does not turn it red. It is covered by the Go replay tests (`internal/replay`, `TestReplay` in `internal/acceptance`) and `scripts/malgw-mutations.sh` ("receive: replay table skipped"), not by this journey.
- The daemon's own revocation checks (send side `Guard.CheckSend`, receive side `Revoked`): the gateway already hides a revoked device, so the journey cannot reach them; they are covered by the Go tests (`internal/receive`, `internal/revocation`, `internal/trust`, `internal/acceptance`) and `scripts/malgw-mutations.sh` ("receive: revocation ignored"), not by this journey.
- A revocation reaching a running daemon by its hourly refresh: the minimum interval is one minute, too slow for CI; the journey restarts the daemon, which reads the list at start.
- A task in flight when its recipient restarts: the caller is not told; the task stays WORKING until it expires or is canceled (the journey cancels it). Whether the caller should be told is a product question for the author.
- The approval timeout (JG-01, "no answer in 5 min is REJECTED"): the gate's timeout is fixed at five minutes and the journey would wait that long; the Go tests cover it (`internal/approval`). Approval itself is in the journey, see above. JG-01 stays `planned` until the timeout and the reference-bot cases have a journey test.
- Queued retention with a dropped connection: `make queued-ttl` (about 17 minutes; `.github/workflows/queued-ttl.yml` runs it nightly and on demand on macOS and Linux, not as a required check).
