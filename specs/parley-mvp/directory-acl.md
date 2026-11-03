# Directory, groups and ACLs (T303)

Gateway: `gateway/src/acl.ts` (tier 1, pure rules), `gateway/src/tenant.ts` (storage), `gateway/src/directory.ts` (HTTP).

## Authority boundary

The gateway's directory rules are **visibility only, and advisory**. Authority to call a bot is the target daemon's identity allowlist from the root-signed binding (plan.md, "Unauthorized caller"). The gateway stores no allowlist, `resolve` returns "visible", never "permitted", and nothing here can grant access the binding does not. A wrong, buggy or malicious gateway can change what is discovered, not who may call. Unauthorized and nonexistent look the same (the card is absent).

## Evaluation (default deny)

There are no allow or deny rules, so no precedence between them. A card has one mode; `canSee` answers by the first match:

1. no viewer identity: hidden
2. viewer is the card's owner: visible (every mode)
3. `tenant`: visible
4. `groups`: visible only if the viewer is in a listed group that exists now; deleted, renamed, empty and unknown groups match nobody
5. `private`, or any unknown or malformed mode: hidden

Identities and group names compare case-insensitively (names are trimmed). Matrix: `canSee matrix` in `gateway/test/acl.test.ts`; lifecycle (delete, rename, empty, unknown group) in `directory.test.ts`. The end-to-end matrix against a daemon allowlist is T307.

## Isolation

One Tenant DO per tenant, named by the authenticated tenant; every key lives in that DO. Device ids are exactly 32 lowercase hex, card ids `<device>:<16 hex>`, both checked before use; tenant ids `[A-Za-z0-9_-]{1,64}`.

## Content and limits

Plaintext metadata only (name 64, description 500, 10 tags of 32, 5 examples of 200, 10 groups of 64 per card), display-text validated (no control, bidi or format characters), secrets linted. 20 cards per device, 2000 per tenant, 100 groups, 500 members and 60,000 member characters per group, 500 audit events. Reads are bounded by those limits.

## Pagination

`find`, `groups`, `groups/get` and `audit` take `limit` (default 25, max 100) and `cursor`, and return `next_cursor` when more remain. A cursor is the hex of the last item's sort key (card: lowercase name, then id; group: name; member: address; audit: sequence), so pages stay stable while items are added or removed.

## Admin and audit

Group routes and `/v1/admin/audit` accept only the admin identity. The identity is still the `DEV_AUTH` placeholder shared with enrollment; this change does not widen it, and sessions replace it when the dashboard auth lands. Group puts and deletes, card publishes and removes, and revocation lists are recorded as metadata events (action, actor, subject, counts; never member addresses or card text), each committed in the same write as the change.

## Revocation

A device named in the stored signed revocation list leaves the directory at once: its cards are deleted in the commit that stores the list, and reads ignore its cards and refuse it. An enrollment that is purged also removes its cards (alarm), and reads ignore them meanwhile.
