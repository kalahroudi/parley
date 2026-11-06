# What Cloudflare retains, and R2 deletion (T308)

Measures two things the spec leaves open: what Cloudflare keeps of data we delete from a Durable Object (the recovery-bookmark test), and what R2 deletion does ("Anything R2-related is claimed only as 'deleted from our bucket' until R2 deletion semantics are verified").

## Status

| | State |
|---|---|
| Measurement Worker, runner, verdict logic and safety rails | Built and tested (`tests/reality/cf/retention*.{ts,mjs}`, `tests/reality/cf/safety.test.mjs`). |
| R2 delete, overwrite, multipart and batch semantics | Checked against the **local runtime only** (miniflare R2). That is a stand-in, not Cloudflare. |
| Durable Object recovery bookmarks | **Not measured.** The local runtime returns an all-zero placeholder bookmark and restores nothing; only Cloudflare keeps history. The local test asserts this, so it fails when the runtime starts returning real bookmarks. |
| Run on the real account | **Not run.** It creates a `parley-test-*` bucket and Worker, which reality check 1 excluded ("no D1, KV or R2"), so it needs the account owner's go-ahead. It belongs to reality check 2 (T309). |

Until the run is committed, the wording stays as in the spec and in `retention.md`: deleted ciphertext **may** persist in Cloudflare's 30-day recovery history (Cloudflare's documentation for SQLite-backed Durable Objects, not yet reproduced by us), and R2 data is claimed only as **deleted from our bucket**.

`tests/pending-t308-cloudflare.test.mjs` tracks the run: it skips while T309 is open, fails once T309 is ticked without `retention-reality-data.json`, and once that file exists it rejects a result that failed, left resources behind, did not come from Cloudflare, has an unmeasured finding, or whose stored verdict does not follow from its observations.

## What the run does

`node tests/reality/cf/retention-run.mjs --out specs/parley-mvp/retention-reality-data.json`, with `PARLEY_REALITY_REAL=1` and `PARLEY_CF_ACCOUNT_ID` set to the pinned account (checked against `cf accounts list`, as in reality check 1). One Worker and one R2 bucket, both named `parley-test-r2-<hex>`, workers.dev only, no other binding. Both are deleted in a `finally` block and the run fails if any `parley-test-*` Worker or bucket remains. Cost: a few dozen requests and one 5 MiB multipart upload deleted at once, inside the free allowances. The data written is random and never returned or stored; the result holds booleans, sizes, timings and error text.

**Durable Object (class `Vault`, SQLite-backed, shaped like the Task DO's storage).**
1. Write a key-value row and an SQL row, take a bookmark, delete both, confirm they are gone, restore the bookmark: are they back?
2. The product's TTL path: hold a row with an alarm, bookmark, let the alarm delete it, restore: is it back?
3. `deleteAll()` (the 90-day metadata purge), then restore.
4. A bookmark for one second ago is issued; one for 31 days ago is refused. This shows where the window ends for new bookmarks, not when stored history is physically erased.

**R2.** Put, then delete: absent from `head`, `get` and `list` at once and after a pause; deleting a missing key is not an error; an overwritten object is gone after one delete; a completed multipart upload is gone after delete; an aborted one leaves nothing; a batch delete removes every key.

## How to read a result

Each finding is `confirmed`, `refuted`, `not measured` or `incomplete`. A `refuted` recovery finding would mean Cloudflare did not return deleted data, and the wording can then be tightened; `confirmed` means the 30-day statement is observed, not only documented. R2 findings can only show absence through the API. That R2 erases the bytes physically is **not observable** and stays `not measured`, so the claim remains "deleted from our bucket" whatever the run shows.

What a confirmed recovery means for G2: deleted ciphertext is readable by whoever can restore the object, which is Cloudflare and anyone with our account credentials. Held events are sealed to keys we never hold, and for processed tasks to keys the device has erased, so the exposure is ciphertext only. Plaintext never reaches the object.
