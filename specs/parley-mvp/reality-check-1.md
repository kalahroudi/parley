# Reality check 1 (T109)

**Status: NOT RUN.** The tooling is in `tests/reality/` and is unit tested against an in-memory gateway, but the check needs a real Cloudflare account, a Google OAuth client and an Entra app registration, which the tooling cannot create. Until the tables below are filled from a real run, T109 stays unchecked in [tasks.md](tasks.md). A section that was not run renders as `NOT RUN`.

Plan reference: "Local-first development", the first of two reality checks. It answers what the local runtime cannot: do the platform limits, costs, hibernation timing, deploy-driven disconnects and real logins match what Phase 1 assumed? What Cloudflare retains after deletion and R2 deletion behavior belong to reality check 2 (T309), because Phase 1 stores no task ciphertext.

## Setup (once)

Use a throwaway Worker and account resources, never the production name.

1. `cd gateway && npx wrangler deploy --name parley-reality-1 --var DEV_AUTH:1`. `DEV_AUTH=1` accepts `Bearer dev:<tenant>:<device>` from anyone, so the probes can connect without enrollment. Delete the Worker when finished (step "Teardown").
2. Real logins need secrets, set with `wrangler secret put` (never in the repo, never in `--var`): `FLOW_SECRET` (random), `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`. Register `https://parley-reality-1.<subdomain>.workers.dev/auth/google/callback` and `/auth/entra/callback` as redirect URIs.
3. Note the Workers plan (Free or Paid) and the date. Durable Objects with SQLite storage run on both, with different limits, so record which one was used.

```
export URL=https://parley-reality-1.<subdomain>.workers.dev
```

## Checks

Results merge into `tests/reality/results.json` (git-ignored; timings and counters only, no frame bodies and no tokens). `node tests/reality/probe.mjs report --out /tmp/r1.md` renders them; paste the output into "Results" below.

| Check | Command | What to look at |
|---|---|---|
| Limits | `node tests/reality/probe.mjs limits --url $URL` | The gateway's 1 MiB frame cap is what refuses an oversize frame (close 1009), not an earlier platform limit. Also read the Workers and Durable Objects limits pages for CPU time, subrequests, WebSocket connections per object and storage per object, and note any that Phase 2 or 3 designs would hit (for example a Tenant DO serving a large tenant) |
| Hibernation timing | `... hibernation --url $URL --idle 10,60,300,1800` and again with `--heartbeat` | Whether an idle socket survives each period, with and without 20 s pings; cold minus warm round trip (the cost of waking the object); that `resume` reports the last `rx_seq`, so storage survived hibernation. If idle sockets are closed by the platform, record after how long, because the daemon's heartbeat and backoff depend on it |
| Deploy-driven disconnects | `... deploy --url $URL --minutes 5`, and while it runs change `gateway/src` trivially and `wrangler deploy` twice, a minute apart | Close code and downtime of each disconnect, that the session resumed, and zero lost and zero duplicate acknowledgements. Compare with the T108 model, which evicts the object and closes its sockets |
| Costs | Read the Workers and Durable Objects usage for the check window from the dashboard (or `wrangler tail` counts) into `usage.json`: `{requests, wsMessages, durationSeconds, memoryMb, rowsRead, rowsWritten, storageGb}`. First copy the current prices into `tests/reality/pricing.json` with their source and date. Then `... cost --usage usage.json --messages-per-day N --awake-seconds-per-day N` | The bill for the window, and the marginal monthly cost of one device. Compare the dashboard's billed figures with the estimate; a gap means the model (20:1 WebSocket messages, duration only while awake) is wrong |
| Real logins | `GOOGLE_CLIENT_ID=... ENTRA_CLIENT_ID=... ENTRA_TENANT_ID=... node tests/reality/probe.mjs logins --url $URL` | The script checks that each `/auth/<provider>/login` redirects to the real IdP with PKCE S256, state, nonce and the right callback. Then in a browser sign in with a real account of each kind and record whether the callback returned an identity. Cover: a Workspace account with and without `GOOGLE_HOSTED_DOMAIN`, a personal Google account, an Entra account in the configured tenant, an Entra guest or other-tenant account (must be refused), and `email_verified` / missing-email behavior. Do not paste the email or `sub` here |

Edit `results.json` by hand to fill `signedIn`, `identity` and `notes` for each login row, then render the report again.

## Teardown

`npx wrangler delete --name parley-reality-1`, remove the OAuth client and app registration redirect URIs added for the check, and delete the secrets. Confirm the Worker no longer answers `/healthz`.

## Results

NOT RUN. Paste the rendered report here, then list every mismatch with the plan as a follow-up task (limits that change a design, hibernation or deploy behavior that differs from T108, a cost per device that changes the seat price, a login case that fails).
