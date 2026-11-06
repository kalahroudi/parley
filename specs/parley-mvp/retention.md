# Retention modes (T304)

Gateway: `gateway/src/task.ts` (held events, TTL, deletion), `gateway/src/device.ts` (push on reconnect, acknowledgment), `gateway/src/a2a.ts` (mode choice), `gateway/src/tenant.ts` and `directory.ts` (the setting).

## What is stored

| | Strict (default) | Queued |
|---|---|---|
| Task frames to the target | relayed, never stored | relayed, never stored |
| Results and status to the caller | relayed only while the caller is connected; otherwise the task fails ("disconnected") | relayed if connected; otherwise the sealed event is held in the Task DO |
| Caller's messages to the target (reply, cancel) | relayed, never stored | relayed, never stored |
| Metadata (ids, states, counters, times) | 90 days | 90 days, plus `ciphertext_deleted_at` |

A held event is the exact event body the daemon would have received: the sealed envelope and routing hints, nothing readable. Only target-to-caller messages are held; the Task DO refuses to hold anything else.

## Setting

Unset, a tenant is Strict. This change holds no R2 objects (none exist yet): T307 proves deletion of encrypted files and T308 documents what Cloudflare retains. Limits are per task (16 events, 4 MiB) and per caller device (256 tasks), which bounds a tenant by its enrolled devices.

`POST /v1/admin/retention` (admin, body `{}`) returns `{mode, queue_ttl_ms}`. `POST /v1/admin/retention/put` with `{mode: "strict"|"queued", queue_ttl_ms?}` sets it (TTL 15 min to 24 h, default 1 h, kept when omitted) and writes a `retention.put` audit event. A task keeps the mode it was created under; a TTL change applies to events held from then on.

## Lifecycle of a held event

1. The target's message cannot be delivered because the caller is offline: the Device DO of the caller notes the task (ids and a deadline, at most 256 tasks), and the Task DO stores the event (at most 16 events and 4 MiB per task) with `exp = now + TTL`. If either refuses, the task fails as in Strict.
2. When the caller's daemon connects, the Device DO pushes every held event, oldest first, with fresh tunnel sequence numbers.
3. Deletion, whichever comes first:
   - **Acknowledgment.** A tunnel `ack` for an event's sequence number (or a later `hello` whose `last_rx` covers it) deletes it. Events not acknowledged are pushed again after the next reconnect; daemons drop duplicates with their replay table.
   - **TTL.** The Task DO alarm deletes events whose `exp` has passed. Reads never return an expired event, even before the alarm runs.
4. When the last held event is gone, the record gets `ciphertext_deleted_at` (shown in the task's `metadata.parley`). Holding a new event clears it.

Cancel, expiry and a dropped Strict socket delete every held event at once. The 90-day metadata purge deletes everything in the Task DO, held events included.

## Claims

"Deleted from our storage" means our Durable Object storage. Cloudflare may keep deleted data in its 30-day recovery history (T308 built the measurement; `retention-reality.md` says what is and is not yet measured on Cloudflare); held events are sealed to keys we never hold, and for processed tasks to keys the device has erased.

## Known limits

- A caller whose socket drops while a task is still running is detected when the target next reports, not at the moment of the drop (Strict). A task already COMPLETED stays COMPLETED even if the result could not be relayed (the target gets an "offline" error). Closing that gap needs a decision on whether a lost result should fail a completed task.
- The Device DO's notes for a task whose events are gone are removed at the next connection or at their deadline, whichever is first.
