# Attack matrix (spike 3)

Every attack in [plan.md](plan.md) (spike 3, "Crypto" and "Prekeys", and the
adversarial harness in the design principles) mapped to the test that proves it
is rejected or detected. `internal/acceptance/matrix_test.go` reads this file:
a row whose test or subtest does not exist, a plan item with no row, or an
attack test in the malicious-gateway files that no row names, fails `go test`.

Outcome: **control** is the honest-gateway baseline (no attack), so the attack tests can only fail because of their attack; **rejected** means the receiver or caller refuses the input and nothing
runs; **detected** means the attack succeeds at the gateway but shows up (a gap,
a failed task, an expired key) and cannot make the victim act on forged data.
A row marked `pending T3xx` depends on a task that is not built; its test is a
`TestPending_` function that skips while the task is open and fails once
`tasks.md` ticks it (`pending()` in `spike3_prekeys_test.go`), so it cannot be
forgotten. Tests are in `internal/acceptance` and run with
`go test -race ./internal/acceptance` (also from `tests/acceptance.test.mjs`).

The table is parsed by column: id, plan item (the key the test checks against
plan.md), attack, outcome, test, subtest (exact `t.Run` name, or `-`).

| id | plan item | attack | outcome | test | subtest |
|---|---|---|---|---|---|
| A01 | substitute keys | gateway serves a binding it signed itself | rejected | TestKeySubstitution | a binding signed by the gateway, not the root |
| A02 | substitute keys | genuine binding of another device under the target's name | rejected | TestKeySubstitution | a genuine binding for another device under the target's name |
| A03 | substitute keys | old genuine binding served after a re-approval (rollback) | rejected | TestKeySubstitution | an old genuine binding served after a re-approval |
| A04 | substitute keys | prekey for the gateway's own key | rejected | TestKeySubstitution | a prekey for the gateway's own key |
| A05 | substitute keys | genuine prekey with the public key swapped | rejected | TestKeySubstitution | a genuine prekey with its public key swapped |
| A06 | substitute keys | task forged in the caller's name to the real prekey | rejected | TestKeySubstitution | a task forged in alice's name to bob's real prekey |
| A07 | substitute keys | embedded prekey object that is not the target's | rejected | TestKeySubstitution | a task whose embedded prekey object is not bob's changes nothing |
| A08 | replay | task delivered twice | rejected | TestReplay | a task delivered twice runs once |
| A09 | replay | frame duplicated by the gateway in one hop | rejected | TestReplay | the same frame duplicated by the gateway in one hop |
| A10 | replay | reply delivered again | rejected | TestReplay | a reply delivered again is caught by the replay table |
| A11 | replay | task replayed after its expiry | rejected | TestReplay | a task replayed after its expiry |
| A12 | replay | CANCEL replayed | rejected | TestReplay | a cancel replayed |
| A13 | replay | caller's own task reflected back | rejected | TestReplay | alice's own task reflected back to her |
| A14 | replay | target's reply reflected back | rejected | TestReplay | bob's reply reflected back to bob |
| A15 | reorder | sequence number rewritten in flight | rejected | TestReorder | a sequence number rewritten in flight |
| A16 | reorder | correctly numbered reply that does not chain | rejected | TestReorder | a correctly numbered reply that does not chain to the last one |
| A17 | reorder | CANCEL overtakes its task | detected | TestReorder | a cancel that overtakes its task |
| A18 | drop | dropped reply shows as a gap | detected | TestDrop | a dropped reply shows as a gap and later ones are held back |
| A19 | drop | dropped final result | detected | TestDrop | a dropped final result fails the task at its expiry and erases the key |
| A20 | drop cancel | dropped CANCEL, late replies refused | detected | TestDrop | a dropped cancel is detected and late replies are refused |
| A21 | drop | dropped task leaves a prekey that expires | detected | TestDrop | a dropped task leaves a prekey that expires and is erased |
| A22 | swap replies | reply relabelled as another task's | rejected | TestSwappedReplies | task one's reply relabelled as task two's |
| A23 | swap replies | ciphertext under another reply's header | rejected | TestSwappedReplies | the ciphertext of one reply under another's header |
| A24 | swap replies | reply delivered to the wrong device | rejected | TestSwappedReplies | a reply delivered to the wrong device |
| A25 | swap replies | another approved device answers for the target | rejected | TestSwappedReplies | a root-approved device answers for bob |
| A26 | swap replies | signature of another message | rejected | TestSwappedReplies | the signature of another message |
| A27 | swap replies | gateway state code taken as truth | rejected | TestSwappedReplies | the gateway's state code is only a hint |
| A28 | withheld prekeys | prekey reply withheld | detected | TestWithheldPrekeys | a withheld prekey reply sends nothing and the issued key expires |
| A29 | withheld prekeys | task held back past expiry | rejected | TestWithheldPrekeys | a task held back past expiry is refused and its key is gone |
| A30 | withheld prekeys | task held back and delivered inside the window | detected | TestWithheldPrekeys | a task held back and delivered inside the window is accepted (documented residual) |
| A31 | withheld prekeys | captured frame opened again after processing | rejected | TestWithheldPrekeys | a processed task cannot be opened again from a captured frame |
| A32 | reused prekeys | old prekey served for a new request | rejected | TestReusedPrekeys | an old prekey served for a new request |
| A33 | reused prekeys | one caller's prekey served to another | rejected | TestReusedPrekeys | alice's prekey served to carol |
| A34 | reused prekeys | prekey cached past its expiry | rejected | TestReusedPrekeys | a prekey cached past its expiry |
| A35 | reused prekeys | two tasks sealed to one prekey | rejected | TestReusedPrekeys | two tasks sealed to one prekey: only the first opens |
| A36 | junk frames | junk frames cannot burn a key or fill the replay table | rejected | TestJunkFramesBurnNothing | - |
| A37 | junk frames | signed but unopenable frame burns nothing | rejected | TestSignedButUnopenableBurnsNothing | - |
| A38 | junk frames | junk of every kind before the real frame | rejected | TestJunkFramesCannotBurnKeys | - |
| A39 | clock attacks | future, expired and far-ahead-clock frames | rejected | TestClocks | a task from the future is refused and not burned |
| A40 | clock attacks | frame at the instant of its expiry | rejected | TestClocks | a task at the instant of its expiry is refused |
| A41 | clock attacks | reply past its expiry | rejected | TestClocks | a reply past its expiry is refused |
| A42 | clock attacks | prekey from a clock far ahead | rejected | TestClocks | a prekey from a clock far ahead is not trusted |
| A43 | wrong direction | reply-type frame for a task this device received | rejected | TestWrongDirection | a reply-type frame for a task this device received |
| A44 | wrong direction | task sealed to a prekey never issued | rejected | TestWrongDirection | a task sealed to a prekey the target never issued |
| A45 | wrong direction | CANCEL from a device that is not the caller | rejected | TestWrongDirection | a cancel from a device that is not the caller, with a leaked follow-up key |
| A46 | sender policy | task for another tenant | rejected | TestWrongDirection | a task for another tenant |
| A47 | sender policy | revoked sender | rejected | TestSenderPolicy | a revoked sender |
| A48 | sender policy | owner the allowlist refuses | rejected | TestSenderPolicy | an owner the allowlist refuses |
| A49 | sender policy | binding version the sender does not carry | rejected | TestSenderPolicy | a binding version the sender's binding does not carry |
| A50 | redelivery | whole backlog redelivered after a reconnect | rejected | TestReconnectAndRestart | the whole backlog redelivered after a reconnect, twice |
| A51 | redelivery | captured task after the target restarts | rejected | TestReconnectAndRestart | a captured task after the target restarts |
| A52 | redelivery | delivered task replayed after a restart | rejected | TestReconnectAndRestart | a delivered task replayed after the target restarts |
| A53 | quota | flood of authentic tasks to prekeys that do not exist cannot fill the replay table | rejected | TestQuota | - |
| A54 | crash between open and ack | crash after open, before ack: clean fail, resend works | rejected | TestCrashPointsFailCleanAndResend | - |
| A55 | crash between erase and execute | crash after erase, before execute: clean fail, resend works | rejected | TestCrashPointsFailCleanAndResend | - |
| A56 | crash between erase and execute | crash during execute does not run twice | rejected | TestCrashDuringExecuteDoesNotRunTwice | - |
| A57 | prekey expires while waiting | caller refuses an expired prekey | rejected | TestPrekeyExpiresWhileSenderWaits | the caller refuses an expired prekey |
| A58 | prekey expires while waiting | target refuses a task whose own expiry passed | rejected | TestPrekeyExpiresWhileSenderWaits | the target refuses a task whose own expiry passed |
| A59 | prekey expires while waiting | target refuses a frame sealed to an expired prekey | rejected | TestPrekeyExpiresWhileSenderWaits | the target refuses a frame sealed to an expired prekey |
| A60 | redelivered frame | redelivered frame is dropped | rejected | TestRedeliveredFrameIsDropped | - |
| A61 | prekey flood, device | one caller cannot hold more than its share of prekeys | rejected | TestPrekeyRequestFloodIsLimited | - |
| A62 | prekey flood, gateway | a flood of sends aimed at one connected target is refused by the gateway's per-device limiter (the RateLimit DO) before it reaches the target, and an honest caller is still served (shipped gateway test) | rejected | TestGatewayRateLimitsFloodToTarget | - |
| A63 | follow-up chain | five-message chain erases each key | rejected | TestFollowUpChainErasesEachKey | after a restart |
| A64 | late reply after CANCEL | reply key erased on CANCEL or FAILED; late reply refused by the device and by the shipped Task DO, also after a restart | rejected | TestLateReplyAfterCancelIsRejected | after a restart |
| A65 | disk clone | disk clone or restored backup holds no usable keys | rejected | TestDiskCloneAndBackupHoldNoKeys | - |
| A66 | restart invariant | replay safety across a restart relies on memory-only prekeys | rejected | TestRestartInvariant | - |
| A67 | core dump and swap | core-dump and swap scans find no key bytes: a scan of the daemon's address space finds no erased key in the locked region (also TestHardenedCrashLeavesNoCore, TestKeyMemoryIsLockedAgainstSwap; scan runs on Linux) | rejected | TestAddressSpaceHoldsNoErasedKey | - |
| A68 | harness control | no attack: an honest gateway delivers tasks, replies and CANCEL (so the attack tests fail only because of the attack) | control | TestHonestGateway | - |
| A69 | prekey flood, gateway | the same flood made of prekey requests through the prekey relay: counted per caller, per target and per tenant, and refused for senders that are revoked or may not see the target | rejected | TestGatewayRelaysPrekeyRequestsThroughTheLimiter | - |
