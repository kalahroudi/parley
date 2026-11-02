# Reality check 1 (T109)

**Status: Cloudflare half in progress; real Google and Entra logins pending the user (see "Real logins").**

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

Pending.
