# Message flow (T412)

How a daemon moves a task in both directions, and what the gateway does for it. Code: `internal/pipeline` (wiring and the per-task chain), `internal/frames` (parsers of untrusted input), `internal/receive` (the at-most-once order), `gateway/src/device.ts` (the prekey relay). The guarantees are in [plan.md](plan.md); the frame and payload formats are in [message-pipeline.md](message-pipeline.md); this file records the relay frames and the decisions the code makes.

## Prekey relay (tunnel frames)

A caller asks the target, through the live relay, for a one-time prekey. Frames are JSON bodies inside tunnel frames. A daemon names the other end in `to`; the gateway rewrites it into `from` with the sender it authenticated (the Worker passes the verified tenant and device to the Device DO; a client's own headers are overwritten). A daemon never trusts a claimed sender, and the target still checks the caller itself (binding, revocation, allowlist), so the gateway only forwards.

| Direction | Frame | Fields |
|---|---|---|
| caller to gateway | `prekey_request` | `id`, `to`, `nonce` (base64, 1 to 32 bytes), `expires_at` (ms, the task expiry) |
| gateway to target | `prekey_request` | `id`, `from`, `nonce`, `expires_at` |
| target to gateway | `prekey_reply` | `id`, `to`, `prekey` (base64, the signed prekey, at most 1 KiB) |
| gateway to caller | `prekey_reply` | `id`, `from`, `prekey` |
| target to gateway | `prekey_refused` | `id`, `to` |
| gateway to caller | `prekey_refused` | `id`, `from`, `reason` (`refused`, `offline`, `rate_limited`), `retry_after_ms` for `rate_limited` |

Every frame is counted against the sender's allowance (scope `prekey`, `RATE_PREKEY_PER_MIN`, default 300; the tenant's is ten times that) before it is delivered, so a flood is refused at the gateway and never reaches the target. A request the gateway cannot deliver is answered to the requester with `offline`, which the sender's outbox treats as "wait and ask again". The gateway stores nothing from these frames. Presence is learned from that answer; there is no presence endpoint.

The sealed task, status, result and cancel messages travel over the A2A endpoint (`SendMessage`, `CancelTask`) as before and reach the peer as tunnel events.

## Keys and chains

- The caller issues its reply key (rpk) from its own pool, puts the public half in the TASK header and the signed prekey object inside the sealed payload, so the target knows the key's id and can check it against the caller's binding.
- The target seals every reply to the rpk, which stays until the last reply (RESULT, ERROR or the CANCEL acknowledgment), a cancel that was never acknowledged (after 30 s) or the task's expiry, and is then erased.
- Each non-final reply carries a fresh one-time key for the caller's next follow-up (REPLY or CANCEL), and the target erases the one it replaces. The caller uses that key once; with none it waits for the target's next message.
- Each direction is a chain rooted at the TASK header: sequence numbers 1, 2, ... and the hash of the sender's previous message. A message that does not continue its chain, comes from another device, is sealed to another key or arrives after a cancel is refused before its key is spent (`receive.Config.Admit`), so a foreign or out-of-order message cannot burn a key.
- Sending needs, before anything is generated or sent: this device's own binding at the version its prekeys carry, a fresh revocation list that does not revoke this device, the target's binding verified by `trust.Daemon.AuthorizeSend` (root signature, rollback store, revocation list) and, after the answer, the prekey verified against the target's binding and the caller's own nonce.

## What this does not do

- **Peer bindings.** `daemon.Deps.Directory` is a seam; no gateway endpoint serves a peer's binding yet, so a real daemon rejects everything until one exists. Pending test `TestPending_DaemonFindsPeerBindingsThroughTheGateway` (T414).
- **The acknowledgment step.** The tunnel acknowledges an event to the gateway when it hands it to the daemon, before the pipeline erases the key; what the pipeline calls "ack" is a seam (a no-op), not a second protocol message. A crash between the tunnel's acknowledgment and the erase loses the task, and the caller resends, as the plan states. Moving the transport acknowledgment after the erase needs a tunnel protocol change.
- **Cancel, REPLY and status** are implemented in the pipeline and tested end to end, but nothing user-facing calls them yet (T401 and T413).
- A reply key is reused across a task's replies by design (plan: replies reuse the construction toward rpk). Per-message forward secrecy for replies holds once the key is erased at the end of the task.
