# A2A v1.0 transport (T302): what the gateway sees, and where it departs from the spec

The gateway serves A2A v1.0 over the JSON-RPC binding at `POST /a2a` and the card at
`/.well-known/agent-card.json`. Code: `gateway/src/a2a.ts` (transport), `gateway/src/parts.ts`
(tier 1: the checks on a sealed part), `gateway/src/task.ts` (tier 1: the only place a task changes state).

## What the gateway sees

Ids, state codes, sizes, timestamps, who called whom. Never text, questions, results, errors or file
names. Every message is one part, `{raw, mediaType: "application/vnd.parley.sealed"}`, and `raw` is the
base64 of one envelope (`internal/envelope` `Message.Marshal`). The gateway reads only the envelope's
plaintext header and sizes (`parts.ts`), and refuses a part, field or metadata key that could carry
readable content (`text`, `data`, `url`, `filename`, part or free message `metadata`, `extensions`,
`referenceTaskIds`). Errors are fixed strings; nothing the caller sent is repeated or logged.

Tested by: `gateway/test/a2a.test.ts` (refusals, no echo, storage holds metadata only),
`gateway/test/parts.test.ts` (tier 1), and `tests/canary-acceptance.test.mjs` (canaries for input,
result, status, question, error and file name sent over the tunnel and over `/a2a`, plus hostile
requests with a canary in every unsealed place; zero hits in storage, logs, URLs, headers and bodies).

## The signed message is the truth

The request's routing hints must repeat the envelope's signed header or the request is refused
(`-32602`): tenant and sender (the authenticated ones), task id, context id, recipient, sequence number
and kind (`metadata.parley.kind` may be omitted). The gateway cannot check the signature (it holds no
keys). A daemon takes the sender, recipient, type, task and sequence from the signed header and the
sender's root-signed binding (`internal/receive`), and **never** from the event the gateway relays:
`metadata.parley.from` and the task state in a relayed event are the gateway's say-so.

## State

The Task Durable Object (`task.ts`) is the single source of truth. The transport only asks it to apply
an event; `gateway/test/a2a.test.ts` ("moves a task only where the Task DO's state machine allows")
tries every event from every state and compares with `NEXT`.

| Signed type (`internal/envelope`) | Sent by | Event | State |
|---|---|---|---|
| TASK (1) | caller | create | SUBMITTED |
| STATUS (2) | target | WORKING | WORKING |
| INPUT_REQUIRED (3) | target | INPUT_REQUIRED | INPUT_REQUIRED |
| RESULT (4) | target | COMPLETED | COMPLETED |
| ERROR (5) | target | FAILED, or REJECTED with hint `REJECTED` | FAILED / REJECTED |
| CANCEL (6) | caller, by `CancelTask` | CANCEL | CANCELED |
| REPLY (7) | caller | REPLY, only in INPUT_REQUIRED | WORKING |

REPLY is the caller's signed answer to a question. REJECTED has no type of its own: the signed message
is an ERROR and the daemons decide.

## Limits

One part per message. The ciphertext must be exactly a power-of-two bucket (4 KiB to 512 KiB) plus the
16-byte tag, the header at most 16 KiB, the request body at most one tunnel frame plus 1 KiB. The body is
read through a hard cap (a missing or false `Content-Length` does not make the gateway buffer more), and
the base64 text length is checked before it is decoded. Bigger content is an encrypted file. Task ids in
`GetTask` and `CancelTask` are 32 lowercase hex characters (the 16-byte task id in the header), so an id
cannot carry text into a Durable Object name.

## Departures from A2A v1.0

Checked against the official SDK (`@a2a-js/sdk`) in `gateway/test/a2a.conformance.test.ts`: the card,
every task and message the gateway serves or relays, and the requests it accepts must round-trip
through the SDK's own types; the SDK client works against it. T306 runs the full lifecycle.

| Departure | Why |
|---|---|
| Parts carry only `raw` and `mediaType`; one part per message | anything else is readable by the gateway |
| `taskId` is the hex of the signed 16-byte id; a new task may omit it | the signed id is the id |
| Responses use the task id as `contextId` | the gateway stores no context; the signed one is in the envelope |
| `SendMessage` returns at once (as if `returnImmediately`) | progress comes over the tunnel or `GetTask` |
| No `ListTasks`, `SubscribeToTask`, `SendStreamingMessage`, push notifications, extended card | no per-device task index (T303/T304); the tunnel is the event channel; the card says so |
| `CancelTask` needs the signed CANCEL envelope in `metadata.parley.parts` | a bare cancel looks the same as a gateway forgery |
| Extra error codes -32010 to -32015 | offline, bad sequence, task exists, not permitted, too large, illegal state move |
| `acceptedOutputModes` that exclude the sealed type get -32005 | content is only ever sealed |
