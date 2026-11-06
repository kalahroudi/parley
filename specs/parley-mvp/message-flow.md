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

## Peer bindings and the test bot (T414)

- **Finding a peer.** With no injected directory a daemon asks the gateway for a peer's binding (`POST /v1/directory/binding`, authenticated with an `api` connect token; see [directory-acl.md](directory-acl.md)). The answer is untrusted input: the pipeline verifies root signature, tenant, expiry and rollback before use, and a binding the daemon has verified is kept until it expires, so a peer is looked up once, not per message.
- **The test bot.** Unless `disable_test_bot` is set in `config.json` (or a real bot is supplied), a daemon answers a task with `parley echo: <the task text>` (at most 1 KiB, run in the bot host with its limits) and only for callers whose root-signed binding names the same owner as this device's own. `parley-cli test -to <device id>` sends a random text to such a device and checks the echo, which proves the enrolled devices, the gateway, the prekey exchange, both sealed directions and the bot in one step. A device never answers itself (the pipeline refuses a task from its own device id), so the test needs a second device of the same owner: `enroll` prints a device's id.
- **Starting up.** A daemon that has just started has no revocation list until its first refresh and refuses to send (`not_ready`); `parley-cli test` sends again for its first ten seconds instead of reporting that.
- The real bots (T402) replace the test bot through `Deps.Allow` and `Deps.OnInbound`; until then it is the only bot a daemon runs.

## Keys and chains

- The caller issues its reply key (rpk) from its own pool, puts the public half in the TASK header and the signed prekey object inside the sealed payload, so the target knows the key's id and can check it against the caller's binding.
- The target seals every reply to the rpk, which stays until the last reply (RESULT, ERROR or the CANCEL acknowledgment), a cancel that was never acknowledged (after 30 s) or the task's expiry, and is then erased.
- Each non-final reply carries a fresh one-time key for the caller's next follow-up (REPLY or CANCEL), and the target erases the one it replaces. The caller uses that key once; with none it waits for the target's next message.
- Each direction is a chain rooted at the TASK header: sequence numbers 1, 2, ... and the hash of the sender's previous message. A message that does not continue its chain, comes from another device, is sealed to another key or arrives after a cancel is refused before its key is spent (`receive.Config.Admit`), so a foreign or out-of-order message cannot burn a key.
- Sending needs, before anything is generated or sent: this device's own binding at the version its prekeys carry, a fresh revocation list that does not revoke this device, the target's binding verified by `trust.Daemon.AuthorizeSend` (root signature, rollback store, revocation list) and, after the answer, the prekey verified against the target's binding and the caller's own nonce.

## What this does not do

- **The acknowledgment step.** The tunnel acknowledges an event to the gateway when it hands it to the daemon, before the pipeline erases the key; what the pipeline calls "ack" is a seam (a no-op), not a second protocol message. A crash between the tunnel's acknowledgment and the erase loses the task, and the caller resends, as the plan states. Moving the transport acknowledgment after the erase needs a tunnel protocol change.
- **Cancel, REPLY and status** are implemented in the pipeline and tested end to end, but only the caller interface (T401) and the bot host (T413) call them; the built-in test bot sends one RESULT and nothing else.
- A reply key is reused across a task's replies by design (plan: replies reuse the construction toward rpk). Per-message forward secrecy for replies holds once the key is erased at the end of the task.
