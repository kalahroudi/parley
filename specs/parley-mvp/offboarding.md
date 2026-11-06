# Offboarding, audit CSV, tenant export and deletion (T503)

Journeys I and L. Group memberships are by identity (an email), not by device, so revoking one device does not touch them (the person may have other devices); an admin removes a person with the group routes and by taking them off the user list, which ends their sessions at once. Code: `gateway/src/tenant.ts` (`putRevocations`, `cascade`, `logTask`, `exportSection`, `auditCsv`, `deleteTenant`), `gateway/src/admin.ts` (the three admin routes), `gateway/src/export.ts` (CSV cells), `Task.revoke` and `Task.wipe` (`gateway/src/task.ts`), `Device.revoke` (`gateway/src/device.ts`). Tests: `gateway/test/offboarding.test.ts`.

## Offboarding cascade

The admin's daemon signs a new revocation list and posts it (`POST /v1/admin/revocations`). For every device the list adds, the Tenant DO then, in this order:

1. **Hides its bots**, in the same storage commit that records the list (its cards are deleted, and directory reads ignore a revoked device from then on). This existed before T503.
2. **Notes the cascade** in that same commit (`cascade`: the devices still to close, the devices whose tasks are still to cancel), so a crash after the commit cannot leave a revoked device with an open socket.
3. **Closes the sockets**: `Device.revoke` closes every socket with code 4403 and deletes everything the Device DO holds (session counters, the notes of held events).
4. **Cancels the tasks**: the Tenant DO scans its task log once and calls `Task.revoke` for every unexpired task in which a revoked device is the caller or the target. A live task becomes `CANCELED` with reason `revoked` and its held ciphertext is deleted at once. A task that had already ended keeps its state, but a result still held for a revoked *caller* (Queued) is deleted too, because nobody is left to acknowledge it.

A new connect token, a new challenge and a task from or to the device are refused as before (the revocation list is checked on each use). A task created in the instant between the list being stored and the task being noted is closed when it is noted (`logTask` answers `revoked`, and the caller sees the answer an offline recipient gets, so revocation is not revealed to a prober).

**Budget and retry.** Each step is a call to another Durable Object, and one request may make about 1000 of them. A pass therefore makes at most `CASCADE_CALLS` (200); if work is left (or a call failed) the alarm continues one second later, and again, until nothing is left. Progress is stored after every device and every task row, and every step is safe to repeat. A later list that adds devices while a cascade is under way joins it and restarts the task scan from the first row.

**Sessions.** The admin allowlist was already rechecked on every request. User sessions are now too: a user taken off `USERS` and off the `USER_DOMAINS` loses the session, and with it the right to file enrollment requests, at once. A session is never longer than 8 h (`SESSION_TTL_MS`), so a sign-in to the identity provider is repeated at least that often, inside the 24 h the spec allows; there is no extension, so the 72 h grace for an unreachable identity provider never applies (nobody stays signed in through an outage, they sign in again when it is back).

## What the cascade does not cover

- **The peer is not told by the gateway.** The gateway cannot sign a CANCEL, and a daemon rejects an event without a sealed part, so the other party of a canceled task learns of it from `GetTask` (state `CANCELED`, reason `revoked`) or at the task's expiry. The signed revocation list is what peers enforce (G4); the cascade removes the gateway's side.
- **Tasks beyond the log.** The log holds up to `MAX_TASK_LOG` (10,000) tasks. When it is full the oldest *expired* row makes room; when none has expired, a new task is refused (`-32017`, "too many unexpired tasks"). A live task is therefore never missing from the log, at the price of a tenant limit of 10,000 unexpired tasks at once (at the default limits, 300 new tasks a minute for the 15-minute default expiry is 4,500, under half of it).
- The revocation list is signed by the root holder's daemon, which the gateway cannot check; it acts on the newest list because treating a listed device as gone only hides things (as before).

## Audit CSV

`POST /v1/admin/audit/csv {kind: "admin" | "tasks", limit?, cursor?}` returns `text/csv` (up to `CSV_PAGE_MAX` = 500 rows a page, default 100). The header row is on the first page only, so pages can be joined as they arrive; the next cursor is in the `x-next-cursor` response header (absent on the last page).

- `admin`: time, action, actor, subject, detail (`key=value` pairs, sorted). The admin audit log (group, card, retention and revocation changes, newest 500 events).
- `tasks`: created, task id, caller owner and device, target owner and device, state, reason, updated, **padded size bucket** (of the task message), retention mode, expires at, **ciphertext deleted at**. The facts come from the tenant's task log; the state, reason and times are read from each Task DO now, and a task whose record has been purged (90 days after it ended) shows `PURGED`.

Every cell is neutralized for spreadsheets: a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading apostrophe, and a cell with a comma, quote or line break is quoted (RFC 4180). Owners, group names and card ids are text users chose, so this is a real attack surface (CSV injection), and `src/export.ts` is tier 1.

The CSV is plaintext metadata, as the spec says (who called which bot, when, state codes, size bucket). It holds no task content because the gateway has none.

## Tenant export

`POST /v1/admin/export {section, limit?, cursor?}` where the section is one of `settings` (retention, root public key, revocation list), `devices` (enrollments with their signed bindings), `cards`, `groups` (with members), `audit` and `tasks`. A page is at most 100 items; the cursor is the opaque `next_cursor` of the previous page. Nothing that authenticates anyone is in it: session, enrollment-token, challenge and poll secrets are kept as hashes and are not exported. There is no content section, because there is no content.

## Tenant deletion

`POST /v1/admin/tenant/delete {confirm: "<the tenant's own name>"}`. Any other value (or none) is a `400 confirm_mismatch` and deletes nothing. Then:

1. A `deleting` marker is stored. From then on the tenant admits nothing: no session (the admin's own included), no connect challenge or token, no enrollment, no device sign-in.
2. Credentials and half-finished sign-ins are deleted.
3. Every Task DO in the task log is wiped (record, held events, alarm), then every Device DO of an enrolled device (sockets closed, storage deleted), `PURGE_CALLS` (200) at a time. A pass that cannot finish is continued by the alarm until it does, so a deletion that was started is completed.
4. Last, the Tenant DO's own storage and alarm are deleted, except a **tombstone** (`deleted`): the time, the number of audit events the tenant had and a SHA-256 over them in stored form. It holds no names and no payload; whoever kept an earlier audit export can check it. It is written once, before anything is deleted, so a resumed pass does not change it, and the `deleting` marker is removed only after everything else is gone. The tenant's next admin sees it in the `settings` export section (`deleted`). The response clears the session cookie.

The tombstone is evidence, not an immutable ledger: the gateway operator could in principle remove it, as with any record held by the party it is about. The deletion is **rate limited per tenant** (`RATE_DELETE_PER_MIN`, default 3 a minute, counting wrong names too, so the typed name cannot be guessed at speed); export and the audit CSV have `RATE_ADMIN_PER_MIN` (default 60). The limiter runs after the admin session is verified.

**What is left, and what it is.** Task DOs that are no longer in the log (it keeps the newest 10,000 tasks, and only expired ones leave it) are not reachable from the tenant. They hold metadata only (ids, state, times: the Task DO deletes itself 90 days after the task ended), and no ciphertext: an expired task has had its held events deleted. Rate-limit counters (device ids, one minute) delete themselves. Deleted ciphertext and records may persist in Cloudflare's 30-day recovery history, as in the spec's non-guarantees. Files in R2 are not held by the gateway yet (named pending test `tests/pending-t307.test.mjs`).

## Who may call these routes

Admin sessions only, every route a POST with a JSON body and no identifier in a URL, with the CSRF and Origin rules of every other admin route. A user session gets `403`, no session `401`, a `GET` `405`. The body is at most 2 KiB and an unknown key is a `400`.
