# Reality check 1 (T109)

**Status.** Cloudflare half: measured on 2026-11-02 and 2026-11-03. Limits, hibernation timing and costs are measured, and the 10k soak with the fixed harness ran once on a fresh Worker and **lost and duplicated nothing** (details under "Second soak: result"). The first soak run was not valid. One earlier claim about deploys re-instantiating the object was wrong and is corrected below. Real logins: **Google PASSED on 2026-11-03 with a personal gmail.com account**, which did not exercise the Workspace hosted-domain (`hd`) path; **Entra is pending a client id**.

Versions: wrangler 4.156.1, `cf` 0.15.0, Go 1.27.3, Node 26.11.1, Worker compatibility date 2026-10-01. Raw data: [reality-check-1-data.json](reality-check-1-data.json) (timings and counters only). Worker `parley-test-r1-6d0c01`, deleted at the end; `cf workers scripts search --name parley-test-` on the pinned account returned `[]` afterwards, and again after the later local-only work.

## Rules this run follows

- Account `b891d462...` is pinned in a generated wrangler config and in `CLOUDFLARE_ACCOUNT_ID`, and `cf accounts list` must show it before every deploy, delete or listing (`tests/reality/cf/safety.mjs`, tested in `safety.test.mjs`).
- Only a Worker named `parley-test-*` is created, deployed or deleted. workers.dev only: no routes, domains, previews, D1, KV or R2. The config is generated in the system temp directory (mode 0600) and removed afterwards; the repo's `gateway/wrangler.jsonc` is untouched.
- Everything is deleted in a `finally` block, and a search for `parley-test-` Workers proves none remain.
- No token or OAuth credential is printed, logged or committed. Authentication is wrangler's and `cf`'s own login.

## Plan: expected usage, written before the run

One Worker, `parley-test-r1-<random>`, running the real gateway plus a measurement wrapper (`tests/reality/cf/worker/entry.ts`). The wrapper adds a probe frame (boot id, boot count, age), and token-guarded `/__push`, `/__drop` and `/__counters` routes. A "WS msg" below is an incoming WebSocket message (billed 20:1 as a request); outgoing messages and pings are not billed.

| Experiment | What it does | Worker requests | DO requests (excl. WS msgs) | Incoming WS msgs | Rows written | DO awake time |
|---|---|---|---|---|---|---|
| Setup | 1 deploy, 1 `/healthz` | 2 | 0 | 0 | 0 | 0 |
| Limits | 8 connections, one frame each from 1 KiB to 33 MiB | 8 | 8 | 16 | ~16 | < 30 s |
| Hibernation | idle ladder (2 to 30 s), ping test (80 s), two 10-minute idles (quiet, with 20 s pings): 4 connections | 4 | 4 | ~110 | ~20 (boot counters) | ~12 wakes x ~10 s |
| Deploy with live sockets | 1 idle and 1 busy socket across 1 real deploy; busy sends 5 frames/s for ~40 s | 2 | 2 | ~250 | ~250 | ~60 s |
| Soak | the T108 shape with the Go client: 10,000 frames up, 10,000 events down, 20 forced reconnects of which 3 are real deploys | ~100 (pushes of 100, reconnects, drops) | ~100 | ~30,000 (10k frames, 10k acks of events, plus resends) | ~30,000 | ~5 min |
| **Total** | | **< 200** | **< 200** | **< 31,000 (about 1,550 billed requests)** | **< 31,000** | **< 10 min = < 75 GB-s at 128 MB** |

Stored data stays under 100 KB (counters only), all deleted with the Worker. Real deploys: 5 (1 initial, 1 in the deploy experiment, 3 in the soak). On the Free plan the daily allowances are 100,000 requests, 13,000 GB-s and 100,000 rows written, and this plan stays below all three. Caps and stop conditions: the soak is run once, with 10,000 messages and a 30-minute timeout; control calls stop the run after 15 failures in a row or 60 in total; the run is stopped by hand on any unexplained error rate.

## Results

### Actual usage against the plan (first full run; the second soak has its own table below)

Platform analytics were not available: `cf billing usage` returned 403 for this login, and I did not widen the authentication. The actuals below are the client-side counts and the object's own counters, so they are exact for requests and messages we sent and derived for rows and duration.

| | Plan | Actual |
|---|---|---|
| Real deploys | 5 | 5 in the full run (1 initial, 1 in the deploy experiment, 3 in the soak), plus 2 initial deploys of two smoke runs with only the limits experiment (those Workers were deleted too) |
| Worker requests | < 200 | about 155 (31 WebSocket upgrades, 104 pushes, 17 drops, 2 healthz, 1 counters read) |
| Incoming WebSocket messages | < 31,000 | at least about 20,300 (10,000 frames, up to 10,000 event acks, hellos, ~180 from the other experiments), about 1,015 billed at 20:1. Frames retransmitted after a reconnect were not counted, and with the backlog in this run (see Soak) that could be several thousand more, so the plan's bound is likely but not provably met. Pings are not billed |
| Rows written | < 31,000 | not measured; at most about 31,000 from the code (one row per accepted frame, per event sent and per event acknowledged, plus boot counters) |
| DO awake time | < 75 GB-s | not measured; at most about 75 GB-s (every object awake for the whole 15 minutes is the upper bound) |
| Stored data | < 100 KB | counters only, deleted with the Worker |

Priced at the overage rates as if no allowance applied, the whole run is under $0.05; with the Free or Paid allowances it is $0. The Free daily allowances (100,000 requests, 13,000 GB-s, 100,000 rows written) were not approached. The account's plan could not be read.

Stop conditions: none triggered. Three control calls failed during the soak (against a limit of 15 in a row and 60 in total).

### Limits

| Frame body | Result |
|---|---|
| 1 KiB, 64 KiB, 512 KiB, 1,048,512 B | accepted, acknowledged in 132, 253, 239 and 345 ms (client round trip, includes upload) |
| 1,048,576 B and 1,049,600 B | refused by the gateway's 1 MiB check, close 1009 |
| 8 MiB | close 1009 after 5.1 s |
| 33 MiB (34,603,008 B) | close 1009 after 3.8 s |

The 1 MiB gateway cap (`MAX_FRAME_BYTES`) is the effective limit. The 8 MiB and 33 MiB closes carry the same code, so this run cannot separate the gateway's check from the platform's; the published platform limit is 32 MiB per received WebSocket message.

Published limits relevant to the design, read on 2026-11-02 from developers.cloudflare.com/durable-objects/platform/limits (not measured here): SQLite storage per object 10 GB on Paid (the page says 1 GB on Free in one place and gives no Free figure in the table); key plus value 2 MB; row 2 MB; CPU 30 s per request, configurable to 5 minutes; a soft limit of 1,000 requests per second per object; 100 classes on Free and 500 on Paid. The page states no per-object WebSocket connection limit. I did not test connection counts or fill storage.

### Hibernation timing

One socket, probe after each idle period; "evicted" means the object was constructed again (new boot id, boot counter incremented in storage) since the previous probe.

| Idle before probe | Evicted | First round trip (ms) | Right after (ms) |
|---|---|---|---|
| 2 s, 5 s, 8 s | no | 31, 36, 30 | 28, 29, 27 |
| 10 s, 12 s, 15 s | **yes** | 36, 40, 39 | 27, 26, 33 |
| 20 s | yes | 364 | 102 |
| 30 s | yes | 36 | 30 |

- The object hibernates after between 8 and 10 s without a message (consistent with the roughly 10 s Cloudflare documents elsewhere; the websockets page gives no figure).
- Waking costs little: the first message after hibernation took 5 to 10 ms longer than a warm one (client-measured, including about 25 ms of network). The two slow samples (364 and 102 ms) were both slow warm too, so they look like network jitter and not wake time.
- **Heartbeat pings do not wake or hold an object.** The object was probed, idle 20 s (hibernated), then 20 pings were sent 3 s apart over 60 s. The next probe found a new object only 0 ms old with the boot counter up by exactly 1: the probe woke it, the pings did not. This matches the auto-response design and the published statement that auto-responses are not billed for duration.
- **Idle sockets survive 10 minutes** with or without 20 s pings; both objects hibernated during the wait and woke on the next message (89 ms and 175 ms, single samples). Cloudflare did not close an idle hibernating socket within 10 minutes; longer idle periods were not tested.

### Deploy-driven disconnects

- **A real `wrangler deploy` did not close any socket.** In the deploy experiment (deploy took 14.2 s) one hibernated socket and one busy socket (5 frames per second) both stayed open through the deploy and for 5 s after; neither received a close. In the soak, none of the three real deploys (13 to 14 s each) caused a reconnect in the Go client during the deploy or the 60 s the harness then waited.
- **Correction.** The first run said the deploy re-instantiated the Durable Object with the sockets still attached, from a busy object's age of 17.5 s and a boot counter of 4 after three deploys. The second run refutes that reading: three deploys under continuous traffic (about 50 frames per second) changed no boot id when it was read 3 s after each deploy finished, and the counter was still 1 at the end. The 17.5 s age and the 4 boots in the first run are better explained by hibernation wakes: the deploy experiment's "busy" socket was idle for 20 s before its traffic started, and the first soak's traffic had finished long before its deploys. Whether a deploy replaces a live object, and when, is **not established**. What is established: a connected, busy device sees no interruption from a real deploy, over 7 real deploys with live sockets in the two runs.
- This agrees with the published behavior ("Hibernation API connections persist ... after hibernating"; a forced code update disconnects). It does not show that a deploy can never disconnect or replace the object (the published page describes deferred updates that adopt new code after hibernation): the published page says a forced update does, and I did not test the immediate or deferred update strategies.
- The first workers.dev request after the first deploy returned 404 and `/healthz` answered after 3.3 s on this run (207 ms on an earlier smoke run).

### Soak, first run (T108 shape, real client, real Worker): not valid

Run once: 10,000 frames up, 10,000 events down, the Go tunnel client, 17 server-side closes (code 1012) and 3 real deploys.

| Check | Result |
|---|---|
| Gateway `rx_seq` at the end | 10,000 (every frame accepted once, in order) |
| Events missing, duplicated by sequence, or out of order | 0, 0, 0 |
| Unacknowledged frames at the end | 0 |
| Reconnects | 16 real reconnects after the first connection (the first of the 17 closes landed before the first connection was welcomed); the totals above reconciled after them, but this run did not record whether each welcome reported `resumed` |
| Go test verdict | **FAIL**, on my own assertion: it required 21 connections for 20 forced reconnects, and only 17 occurred because the 3 deploys did not disconnect anything |

**This run does not establish "deploys during traffic lose nothing".** Two defects in the harness, found by reading the result:

1. The sender queued all 10,000 frames in about 0.2 s (`Send` only queues) and the control points were paced by that queued count, so nearly every close and deploy fired against a backlog and not during an even transfer (`at_sent` was 10,000 at 19 of 20 control points).
2. The event pusher ran ahead for the same reason, so the sender's retry path for events lost in flight was never exercised (`events_retried` = 0).

The invariants held, so nothing contradicts the T108 result, but the run did not demonstrate recovery under load. **Fixed, validated locally only:** the harness now paces frames at about 100 per second, counts progress in acknowledged frames, batches event pushes at 100, no longer requires a deploy to disconnect, and fails if no frame was ever unacknowledged at a reconnect (as the T108 test does). Against a local `wrangler dev` it passes with 17 of 17 closes reconnecting, 5 to 10 frames to recover at each reconnect, 101 push calls and 10,000 of 10,000 delivered exactly once. **It has not been re-run against Cloudflare:** the agreed cap was one 10,000-message soak. Re-running costs about the same as the first run (under $0.05 at overage rates): `node tests/reality/cf/run.mjs --only soak`, about 5 minutes, same safety rails. This needs your go-ahead.

### Second soak: pre-run confirmation and plan (written before the run)

Approved by the user as exactly one more run of the fixed 10k soak, against a fresh `parley-test-*` Worker, with the same safety rules. Before spending it, the harness was run against a local `wrangler dev` (no Cloudflare account) and failed twice, which is what it is for:

- It refused a run where `events_retried` was 0. The first fix (pushing events right after a server close) did nothing: after a clean close the gateway answers `offline` at once and sends nothing into the dead socket, which is correct behavior and not a loss. Events are only lost into a half-open link, so the client got the same test seam T108 uses (`mute`, here `deaf`, with a unit test, `TestDeafLinkDiscardsGatewayMessages`): before each of the 17 closes the client is made deaf, the peer pushes 10 events into it, and then the link is closed.
- With that, locally: `events_retried` 170 (17 bursts of 10), all recovered, 0 missing, 0 duplicated, `rx_seq` 10,000, 3 to 5 frames unacknowledged at each of 18 connections, 132 push calls.
- Deploys: the harness reads the Durable Object's boot id before each deploy and 3 s after it, and the run fails unless every deploy either dropped the connection or changed the boot id. A local dev reload showed that observation working (a changed boot id was seen once); a plain file touch does not reload it, so a local run cannot show all three, only the real run can.
- Pacing is now about 50 frames per second (about 200 s of traffic), so the 20 control points land during the transfer, and control points are driven by acknowledged frames.

Expected usage for this run (one Worker, one deploy to create it, 3 deploys during the run):

| | Expected |
|---|---|
| Worker requests | about 180: 18 WebSocket upgrades, about 135 pushes (100 events each, plus 17 bursts), 17 drops, 7 counters reads, 2 healthz |
| DO requests excluding WebSocket messages | about 175 (the RPCs behind those calls plus the upgrades) |
| Incoming WebSocket messages | about 20,100: 10,000 frames, about 10,000 event acks, about 70 retransmitted frames, 18 hellos; about 1,005 billed at 20:1; pings not billed |
| Rows written | at most about 30,300: 10,000 accepted frames, about 10,170 events sent, about 10,000 acknowledgements, 18 hellos, boot counters |
| DO awake time | at most about 33 GB-s (about 260 s of continuous traffic at 128 MB) |
| Stored data | counters only, deleted with the Worker |
| Cost at overage rates, no allowance | about $0.03 (rows written dominate); $0 inside the Free or Paid allowances |

Stop conditions are unchanged: 15 failing control calls in a row or 60 in total, a 25-minute timeout, and any loss or duplicate is reported as a product bug and not tuned away.

### Second soak: result (2026-11-03, 10:45 to 10:49 UTC, Worker `parley-test-r1-608aeb`, deleted)

The one approved re-run: 10,000 frames up and 10,000 events down with the real Go client at about 50 frames per second, 17 closes of the live link and 3 real deploys under traffic (at 2,380, 4,761 and 7,151 acknowledged frames; each deploy took 14 to 15 s). Raw data: [reality-check-1-soak2-data.json](reality-check-1-soak2-data.json).

| Check | Result |
|---|---|
| Gateway `rx_seq` at the end | **10,000** (every frame accepted once, in order) |
| Frames sent, unacknowledged at the end | 10,000, 0 |
| Events missing, out of order or duplicated by sequence | **0, 0, 0** |
| Duplicate event bodies, after sender retries and not | 0, 0 |
| Events lost in flight and retried | **190** (17 bursts of 10 pushed into a half-open link, plus 20 more lost on other drops, not attributed), every one delivered exactly once after the retry |
| Frames unacknowledged at each of the 18 connections (`unackedAtResume`) | 30 (initial send), 13, 15, 14, 10, 20, 43, 13, 13, 15, 15, 12, 15, 13, 14, 17, 13, 17; 302 in all, so about 270 frames were retransmitted after reconnects |
| Closes that reconnected | 17 of 17 (18 connections) |
| Control calls that failed | 0 |
| Real deploys that dropped the connection | **0 of 3** |
| Real deploys that changed the object's boot id (checked 3 s after each) | **0 of 3** |
| Go test verdict | FAIL, on one guard only: "every deploy must disconnect or re-instantiate" |

**Reading the verdict.** No loss and no duplicate occurred, and the run exercised recovery (frames unacknowledged at disconnect, 190 events lost and retried), so the T108 property holds against the real Worker with the real client. The one failed check was a harness guard I wrote to prove the deploys had an effect; the finding is that they had none that the test could see, which is consistent with the first run and the deploy experiment. That is a measurement, not a product defect. After seeing the result I changed the guard from a failure into a recorded observation (`deploys_with_an_observed_effect` in the result, plus a log line), and have **not** re-run it on Cloudflare; the tunnel and gateway code are unchanged by this.

Usage against the plan written before the run:

| | Plan | Actual |
|---|---|---|
| Worker requests | about 180 | about 176: 18 upgrades, 132 push calls, 17 drops, 7 counters reads, 2 healthz |
| Incoming WebSocket messages | about 20,100 | about 20,300: 10,000 frames, about 270 retransmitted frames, 10,000 event acks, 18 hellos; about 1,015 billed at 20:1; pings not billed |
| Rows written | at most about 30,300 | not measured by the platform (analytics are not available to this login); derived about 30,200: 10,000 frames, 10,190 events sent, about 10,000 acks, 18 hellos |
| DO awake time | at most about 33 GB-s | not measured; at most 26 GB-s (207 s of traffic at 128 MB) |
| Real deploys | 3 plus the initial one | 4 |
| Stored data | counters only | deleted with the Worker |

Cost of this run at the overage rates, if no allowance applied: about 1,190 billed DO requests ($0.0002), 176 Worker requests ($0.0001), about 30,200 rows written ($0.030) and 26 GB-s ($0.0003), so **about $0.03**; inside the Free or Paid allowances, $0. Together with the first full run and the two smoke runs, everything spent on the account in this task is under $0.10 even at overage rates. After the run, `cf workers scripts search --name parley-test-` on the pinned account returned `[]`.

### Costs (Workers Paid)

Prices copied on 2026-11-02 into `tests/reality/pricing.json` from the Durable Objects pricing page (last updated 2026-10-18) and the Workers pricing page (last updated 2026-10-02): $5 per month minimum; DO requests 1 million included then $0.15 per million, with incoming WebSocket messages at 20:1 and pings and outgoing messages free; duration 400,000 GB-s included then $12.50 per million GB-s, billed at 128 MB, hibernated and auto-response time not billed; SQLite rows written 50 million included then $1.00 per million; rows read 25 billion included; storage 5 GB-month then $0.20; Worker requests 10 million included then $0.30 per million (WebSocket messages through a Worker are not requests, the upgrade is one).

Per-task usage is an assumption, not a measurement: 11 incoming messages and 30 rows written per task (15 from the Device DO as it is today, 15 allowed for the Task DO of Phase 2), and 0.3 s awake per task. `node tests/reality/cf/cost.mjs` prints:

| Devices | Tasks per device per day | Tasks per month | Billed DO requests | Rows written | Usage USD | Total USD (with the $5 plan) |
|---|---|---|---|---|---|---|
| 10 | 20 | 6,000 | 4,500 | 180,000 | 0.00 | 5.00 |
| 100 | 20 | 60,000 | 45,000 | 1,800,000 | 0.00 | 5.00 |
| 1,000 | 20 | 600,000 | 450,000 | 18,000,000 | 0.00 | 5.00 |
| 1,000 | 100 | 3,000,000 | 1,770,000 | 90,000,000 | 40.12 | 45.12 |
| 5,000 | 100 | 15,000,000 | 8,850,000 | 450,000,000 | 403.21 | 408.21 |

A small tenant (10 devices) costs nothing beyond the plan's $5 minimum; overage starts at about 2,200 devices at 20 tasks per device per day, or 555 at 100. At scale **rows written, not requests or duration, dominate** (90 million rows is $40 of the $40 in the fourth row). Duration is negligible because hibernated objects are not billed. These are projections from stated assumptions; the first measured per-task numbers come with the Phase 2 and 3 task flow.

### Proposals this implies (not applied)

1. **Cut rows written per message.** `Device.webSocketMessage` rewrites the whole session record for every accepted frame, every event sent and every event acknowledged. Counters that only matter after a reconnect could be kept in the socket attachment (which survives hibernation; not shown here to survive a replaced object) or written at most every N messages, with the durable value used only when the attachment is gone. Needs a correctness review against resume after eviction before anyone changes it.
2. **Keep the resume logic and the daemon's reconnect loop.** Deploys did not disconnect sockets here, but the published behavior allows forced disconnects and idle limits can change; nothing observed argues for removing them.
3. **Inline ciphertext tops out at a 512 KiB padding bucket.** Frames are JSON with a base64 body, and the 1 MiB frame cap (accepted up to 1,048,512 B body) leaves room for about 768 KB of raw ciphertext, so the largest power-of-two bucket that fits inline is 512 KiB. Larger payloads go through R2 files. Relevant to T205 and Phase 3.
4. **Do not hold the Device or Task DOs awake.** No timers or intervals in the Device DO, and use alarms for task deadlines only while a deadline is pending, since the published page says timers prevent hibernation.
5. **Retry after the first deploy.** workers.dev can answer 404 for a few seconds on a new Worker; enrollment or setup scripts should poll.

## Real logins (pending the user)

**Google: PASSED on 2026-11-03 (personal gmail.com account); the Workspace hosted-domain (`hd`) path is not covered.** **Entra: pending user: needs client id.** The Google run is recorded under "Result of the user's run" below.

### Google (the OAuth client created for this check)

The client id is public and is baked into `tests/reality/logins/google.mjs`: `221774361645-4isrhvs33j1eft8133hsk239s831d33r.apps.googleusercontent.com`. The **client secret never goes into chat, a file or this repo**; you type it into wrangler's hidden prompt yourself. The secret must be the one for **this** client; an older client's secret will not work.

The check always uses the fixed throwaway Worker `parley-test-login` on account `b891d462...`, so one redirect URI is registered once and stays valid. The account's workers.dev subdomain is `hello-891` (read from a real deploy; the CLI has no command for it). The callback path is `/auth/google/callback` (`gateway/src/auth.ts`).

**Step 1: register the redirect URI (once).** In console.cloud.google.com open the project that owns the client, then Google Auth Platform, Clients, open the client whose id is the one above (its type must be **Web application**), Authorized redirect URIs, Add URI, paste exactly:

```
https://parley-test-login.hello-891.workers.dev/auth/google/callback
```

Save. Google can take a few minutes (rarely longer) to apply it. If the console refuses the URI, send me the exact message. Nothing else on the client needs to change.

**Step 2: consent screen settings that must be true** (Google Auth Platform, Audience / Branding / Data Access):

- Publishing status **Testing** is fine, but then your own Google account must be listed under **Test users** (Audience). Without that, Google shows "Access blocked" and the check cannot pass. **In production** needs no test user.
- User type **Internal** only admits accounts of your Workspace organization; **External** admits any Google account (in Testing, the test users).
- Scopes (Data Access): `openid` and `.../auth/userinfo.email` only. They are not sensitive, so no verification is needed.

**Step 3: run the check.**

```
node tests/reality/logins/google.mjs
```

It verifies the account, deploys the Worker with the client id as a plain variable, and prints the redirect URI and then this command (with the real temp-config path filled in), which you run in a second terminal and answer at the prompt:

```
cd gateway && npx wrangler secret put GOOGLE_CLIENT_SECRET --name parley-test-login --config "<temp config pinned to account b891d462...>"
```

The script notices the secret (it lists secret *names* only) and then runs its first check, before anyone is asked to click: the login redirect must go to Google and name **exactly** the client id above and **exactly** the callback above (compared to fixed constants, not to wherever the Worker happened to deploy), with PKCE S256, a state and a nonce. A mismatch, such as another workers.dev host or a different client, fails there with the exact difference, and the Worker is deleted. If it passes, the script opens the login URL. Sign in and click **Allow** once. The gateway's own callback validates the id token's signature, issuer, audience, nonce and expiry plus the state and PKCE, and, for a hosted-domain run (`--domain`, below), the `hd` claim. The script then prints `PASS` or `REFUSED` with only the provider, issuer, email **domain** and flags (never the email, subject id or tokens; the browser is shown a plain "signed in" page), deletes the Worker in a `finally` block and lists `parley-test-*` Workers to show none remain. Deleting the Worker also deletes the secret, so each run needs the command again. If a run is abandoned, `node tests/reality/logins/google.mjs cleanup` deletes the Worker.

Expected results:

| Case | Run | Expected |
|---|---|---|
| Personal Gmail (a test user) | no `GOOGLE_HOSTED_DOMAIN` | `PASS`, `personalAccount: true`, `hostedDomainChecked: false` |
| Workspace member | `--domain their.domain --mode positive` | `PASS (positive)`, `hostedDomainChecked: true` |
| Personal Gmail | `--domain example.com --mode negative` (any domain the account is not in) | `REFUSED as expected (negative): tenant_mismatch`, no identity issued |
| Consent denied (click Cancel) | any | `REFUSED ... idp_denied` |
| Account not a test user (Testing mode) | any | Google's own "Access blocked" page; no result arrives and the script times out and cleans up |

**Result of the user's run (2026-11-03, account `b891d462...`, the new client).** The user ran `node tests/reality/logins/google.mjs` with a personal Google account and it passed. As reported by the user's run, not re-run by me:

- First check: the login redirect went to Google and named exactly the client id above and exactly the callback `https://parley-test-login.hello-891.workers.dev/auth/google/callback`, with PKCE S256, a state and a nonce.
- Sign-in and one consent click, then: `PASS {"ok":true,"status":200,"provider":"google","issuer":"https://accounts.google.com","emailDomain":"gmail.com","personalAccount":true,"hasSub":true,"hostedDomainChecked":false}`.
- Cleanup: the Worker was deleted and the listing reported `remaining parley-test-* workers: []`. (My own listing at the end of this task agrees, see the final state below.)

What this establishes: against real Google and a real Worker on Cloudflare, the gateway's OIDC code completed the authorization-code flow with PKCE for the registered client and callback, and its id-token checks (signature, issuer, audience, nonce, expiry, state) all passed on a real token, with the client secret set through wrangler's prompt and never seen by any script or chat. The identity came back with the Google issuer and an email on `gmail.com`; nothing beyond the domain is recorded here.

**What it did not cover:**

- **Workspace hosted-domain (`hd`) enforcement.** The run used a personal account with `GOOGLE_HOSTED_DOMAIN` unset (`hostedDomainChecked: false`), so the code path that requires the `hd` claim to equal the configured domain, and the refusal of a personal account when a domain is configured, were **not exercised against real Google**. They remain covered only by the mock-IdP tests. Still to do, now supported by the script (see "Hosted-domain (Workspace) runs"): a negative run with the personal account and a non-matching domain (no Workspace account needed), and a positive run with a real Workspace account.
- The other Google cases in the table: consent denied (`idp_denied`), and an account that is not a test user while the app is in Testing (Google's own "Access blocked").
- **Microsoft Entra:** nothing was run; it is pending a client id.
- Only one sign-in was run, so token expiry and `email_verified: false` behavior were not seen on a real token.

#### Hosted-domain (Workspace) runs

Two runs prove the domain restriction: a positive one with a Workspace account, and a negative one that needs **no Workspace account at all**. Both use the same three steps as above (the redirect URI is already registered; the secret command is re-run each time).

**(a) How the domain gets to the Worker.** Give the script the domain with `--domain corp.example`, or set `GOOGLE_HOSTED_DOMAIN=corp.example` in your shell instead (the flag wins). The script lowercases it, refuses anything that is not a plain domain name, and writes it into the generated, throwaway wrangler config as the Worker's `GOOGLE_HOSTED_DOMAIN` variable when it deploys. There is no wrangler edit for you to make. Before anyone is asked to click, the script's first check confirms the variable arrived: the Worker's login redirect to Google must carry `hd=<your domain>`, and the run stops with "GOOGLE_HOSTED_DOMAIN did not reach the Worker" if it does not. A domain always needs a mode, so a run can never be unclear about what it expects.

**(b) Two modes.**

| Mode | Command | Sign in with | Expected output | Exit code |
|---|---|---|---|---|
| Positive | `node tests/reality/logins/google.mjs --domain corp.example --mode positive` | a Workspace account of `corp.example` | `PASS (positive): an account of corp.example was accepted and the hd claim was checked`, with `hostedDomainChecked: true` | 0 |
| Negative | `node tests/reality/logins/google.mjs --domain example.com --mode negative` | an account that is **not** of that domain, for example the personal gmail.com account you already used | `REFUSED as expected (negative): tenant_mismatch, hd did not match example.com; no identity was issued` | 0 |

The negative run is the one that proves enforcement without a Workspace account: a personal account has no `hd` claim, so a gateway that enforces the domain must refuse it even though the sign-in itself succeeds at Google. Any other outcome exits 1 with a plain reason:

- `ENFORCEMENT FAILED`: the account was accepted although a domain was set. That is a gateway bug; stop and report it.
- `NOT PROVEN (negative)`: it was refused for another reason (you cancelled consent, Google blocked the account, the Worker timed out), so the domain check was not what stopped it. Run it again and click Allow.
- `UNEXPECTED`: a negative refusal that still carried identity fields, or a positive run accepted without the hosted-domain check having run.

On a refusal the gateway answers `{"error":"tenant_mismatch"}` with no identity and sets no cookie; the script prints only the code and flags, and the browser sees a plain "refused" page.

**(c) Consent screen for a Workspace account, and the secret.**

- **External, Testing (recommended for both modes).** Add every account you will sign in with, the Workspace one and the personal one, under Test users (Audience). The negative run needs External: with **Internal**, Google itself blocks a personal account before it reaches the gateway, which gives `NOT PROVEN`. Internal admits only accounts of your Workspace organization, so it suits the positive run alone.
- If the Workspace admin restricts third-party apps (Admin console, Security, API controls), the client must be allowed there, or Google shows an "Access blocked" page for that account and no result arrives.
- Scopes stay `openid` and `.../auth/userinfo.email`; no verification is needed.
- **The secret command must be re-run on every run.** Deleting the Worker at the end of a run deletes its secrets, so each run prints the command again and waits for you to type the client secret at wrangler's hidden prompt. It never goes through chat, a file or the script.

**(d) The `hd` request parameter is only a hint, and the gateway validates the claim.** The `hd` value the gateway adds to the authorization request only steers Google's account chooser; a user can edit it out of the URL and a personal account is never stopped by it. The gateway therefore does not rely on it: `completeLogin` in `gateway/src/oidc.ts` refuses with `tenant_mismatch` unless the `hd` claim of the **signature-verified id token** equals the configured domain exactly. This was checked in the code (no fix was needed) and is pinned by tests in `tests/gateway-oidc.test.mjs`: the hint is sent but the IdP ignores it and issues a token with no `hd` (refused, even with an email on the right domain); look-alike, wrong-case, padded, empty, array and null `hd` values are refused; a matching `hd` on a token whose signature fails is not trusted; and through the gateway callback a refusal returns only the code with no cookie. Removing the claim check makes three of those tests fail (verified by deleting the line and restoring it).

**What was already proven (2026-11-03, with a fake secret).** The full pipeline ran on Cloudflare with a junk value as the secret: deploy, the printed secret command run verbatim, the secret detected, the redirect check against Google's real authorize URL (client id, callback, PKCE S256, state, nonce all correct), a bogus callback instead of a browser (refused as `bad_flow`, recorded as a redacted summary), then delete and a final listing of `[]`. It was run again with the new client id and the exact-match check passed against Google's live authorize URL. What remains unproven is only what needs you: Google accepting the redirect URI and the real consent.

### Microsoft Entra

1. entra.microsoft.com, Identity, Applications, App registrations, New registration. Name it `parley-test`. Supported account types: **Accounts in this organizational directory only (single tenant)**. Redirect URI: platform **Web**, `http://localhost:8787/auth/entra/callback` (Entra accepts plain http only for `localhost`, not `127.0.0.1`).
2. Overview: copy the **Application (client) ID** and **Directory (tenant) ID**.
3. Certificates and secrets, New client secret: copy the secret **Value** at once.
4. API permissions: the default `User.Read` plus the OpenID permissions `openid`, `email`, `profile` (delegated, no admin consent needed).
5. Optional: Token configuration, add the `email` optional claim to the ID token. Without it the gateway falls back to `preferred_username`, which is the sign-in name.
6. In a shell:
   ```
   export ENTRA_TENANT_ID=... ENTRA_CLIENT_ID=... ENTRA_CLIENT_SECRET=...
   REDIRECT_HOST=localhost node tests/reality/logins/verify.mjs entra
   ```

| Case | Expected |
|---|---|
| Member of the tenant | `PASS`, `tenantChecked: true` |
| Guest (B2B) user invited to the tenant | Entra signs them in with `tid` of your tenant, so expect `PASS`; **decide whether guests should be allowed**, since the gateway does not tell members from guests |
| Account in another tenant, or a personal Microsoft account | Refused by Entra itself (single tenant), which the gateway reports as `idp_denied`; if it ever reaches the gateway, `tenant_mismatch` |

### Entra against the deployed gateway

**Pending user: needs client id.** Entra has no existing client yet. After you create the app registration above, send the client id and tenant id (both are identifiers, not secrets; the client secret stays with you) and the Entra check will get the same fixed-name treatment as Google (`parley-test-login`, a registered `/auth/entra/callback` redirect URI, `wrangler secret put ENTRA_CLIENT_SECRET`, one sign-in, clean delete). Until then the loopback script above works on its own.

When done, record in the table below which cases passed, without emails or subject ids.

| Case | Date | Result |
|---|---|---|
| Google, personal (gmail.com) | 2026-11-03 | **PASS** (`personalAccount: true`, `hostedDomainChecked: false`); personal account, no domain configured |
| Google, POSITIVE: Workspace account, `--domain <their domain> --mode positive` | | pending user (needs a real Workspace account) |
| Google, NEGATIVE: personal account, `--domain example.com --mode negative` | | pending user (needs no Workspace account; expect `REFUSED as expected ... tenant_mismatch`) |
| Entra, member | | pending user: needs client id |
| Entra, guest | | pending user: needs client id |
| Entra, other tenant | | pending user: needs client id |
