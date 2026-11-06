# Hostile-input coverage (T404)

Which untrusted input surface is attacked by which test, and what is not yet covered. A cell says what the named tests
pin; "none" is a gap, not an oversight, and each gap has its reason. Go fuzz targets are listed in
`scripts/fuzz-targets.txt`, each with a committed seed corpus under `testdata/fuzz/` and a bounded run in CI
(`node scripts/fuzz.mjs smoke`); a crasher is fixed with a regression seed, never skipped. Written after reviewing PR #70.

| Surface | Attacked by | Not covered (reason) |
|---|---|---|
| Bot output over the API and CLI adapters (stdout lines, HTTP body) | `internal/adapter/hostile_test.go` (end to end through the Host: not JSON, unknown field, trailing text, two values, wrong types, bad base64, status and question floods, a line past the limit, a bot that keeps asking, a second final message, a 100 000-character error cut as valid UTF-8; every case also checks that no goroutine outlives the Host); `wire_internal_test.go` (exact line limit, bounded read); `FuzzReadMessage` | Stalled bot: pinned by `deaf` in `cli_test.go` and the Host timeout, which is a real clock (30 s default); no fake clock exists in the Host yet |
| Task fields sent to a bot (context, caller, owner, content) | `hostile_test.go` `TestHostileTaskFieldsReachTheBotAsOneWellFormedLine` (quotes, newlines, NUL, ESC, invalid UTF-8, injected JSON, 64 KiB) | none |
| Local socket requests (`internal/localsock`) | `TestSocketRejectsMalformedAndOversizedRequests`, `TestSocketRefusesRequestsThatCarryMoreThanTheOneObject` (unknown field, second value, trailing text, invalid UTF-8, NUL), `TestSocketConnectionLimit`, `TestEscapedMaximumRequestAndLargeReplyRoundTrip`, peer-uid tests | Duplicate keys (Go keeps the last; the socket is closed to other OS users and a method sees only `params`); deeply nested `params` (bounded by the 256 KiB read, the method parses it); stalled peer (30 s connection deadline, real clock) |
| MCP server (`internal/mcp`) | `limits_test.go`, `TestAnOversizedLineEndsTheSession`, `TestIDBounds`, `TestArgumentSizeLimitIsExact`, `TestInvalidIDsAreRefusedAndNeverReachTheDaemon`, `TestServeLeavesNoGoroutinesBehind`, `FuzzServe` | Bidi characters in tool arguments |
| Gateway frames to and from the daemon (`internal/frames`) | `FuzzParseEvent`, `FuzzDecodePrekey`, `FuzzUnpackInner`, duplicate and mis-cased keys, nesting, exact limits, `Retry-After` overflow | invalid UTF-8 / bidi in string fields |
| Envelope, padding, files, bindings, revocation, prekeys, replay table | `FuzzMessage`, `FuzzUnpad`, `FuzzUnpadShaped`, `FuzzDecryptFile`, `FuzzDecodeVerify` (binding, revocation), `FuzzIssue`, `FuzzVerify`, `FuzzAccept`, `FuzzReceive` and the exact-limit tests of each package | none |
| Gateway replies to the daemon (trust, connect token, enrollment, directory) | `FuzzGatewayReplies`, `FuzzReplies`, `TestOversizedGatewayRepliesAreRefused`, `TestTokenReplySizeLimitIsExact`, `TestDirectoryReplyLimitsAreExact` | none |
| Pipeline, caller (task payloads, replies, tables) | `TestMalformedTaskPayloadsNeverReachTheBot`, `TestMalformedRepliesAreNotAccepted`, `TestWaitingTableIsBounded`, `TestPendingTasksPerPeerAreBounded`, caller limit tests | none |
| Gateway HTTP and WebSocket (Device DO, connect, enroll, directory, login, session, A2A) | `gateway/test/*.test.ts`: malformed and oversized frames (1009 close at the limit), binary frames, duplicate hello, replayed challenge and cancel, control/bidi characters in names, unknown fields, rate limits and floods, fail-closed limiter | No fuzz target in TypeScript (no corpus tooling in the gateway yet); deeply nested JSON on the A2A endpoint; goroutine/memory ceilings do not apply to Workers (the platform bounds them) |
| Replays | gateway `a2a`, `connect`, `task` tests; `internal/replay`, `TestConcurrentDuplicateWinsOnce` | none |

Because gaps remain, T404 stays open in `tasks.md`.
