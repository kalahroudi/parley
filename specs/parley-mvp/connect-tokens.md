# Device connect tokens (T415)

How a device gets into the gateway. Code: `gateway/src/connect.ts` (Worker, binding and token checks), `Tenant.issueChallenge`, `issueConnectToken` and `connectAuth` (`gateway/src/tenant.ts`), `internal/connect` (daemon client), `internal/daemon` (default tunnel configuration), `internal/tunnel` (`TokenSource`).

## Protocol

1. **Root.** The admin registers the tenant's root public key once (`POST /v1/admin/root`; the same key again is accepted, another is refused). Without it no device connects.
2. `POST /v1/connect/challenge {tenant, device}` returns `{challenge, expires_at}`: 32 random bytes, valid 60 seconds. For a device that may connect, the Tenant DO stores only the challenge's hash (at most 4 outstanding per device, oldest first out, the alarm removes expired ones). For any other device the answer has the same shape and nothing is stored, so the endpoint does not say whether a device exists and costs storage only for real devices.
3. The device signs `Message` with its Ed25519 signing key (from the keystore) and posts `POST /v1/connect/token {tenant, device, challenge, version, scope, signature}`. `Message` is the label `parley/connect/v2`, then length-prefixed (4 bytes, big endian) tenant, device and challenge, the challenge's expiry (unix ms) and the binding version (8 bytes, big endian), and the length-prefixed scope. The same bytes are built in Go, TypeScript and the Node test harness; a vector is checked on both sides.
4. The Tenant DO consumes the challenge first (single use, whatever follows). It then issues a token only if the device is not on the newest revocation list; has an approved enrollment whose binding **the registered root signed** (the gateway verifies the signature over `internal/binding`'s encoding itself, and `not_after`, tenant, device id and key, on every issue and every use, not a stored copy of a key); the binding version equals the signed `version`; and the signature verifies against the key in that binding. Every refusal is the same `401 {"error":"unauthorized"}`.
5. The token is `pdt_<tenant>.<device>.<secret>`, 256 bits, valid 5 minutes, stored only as a hash, bound to tenant, device, binding version and scope. A device keeps at most 8; the oldest go first.

## Scopes and what a token opens

- `connect`: opens `/v1/connect` and is **consumed by the upgrade that presents it** (single use). Nothing else.
- `api`: serves `/a2a` until it expires (not single use: these are separate requests). The device routes (`/v1/cards/*`, `/v1/directory/*`) still have no device credential wired in.

The token travels only in the `Authorization` header over TLS; a token in a query string or a subprotocol is not a credential. The tenant and device come from the token and its record must exist in that tenant's Durable Object, so a token never reaches another tenant's or another device's resources. Each use re-checks the device is still connectable at the token's binding version: a revocation, an expired binding or a newer binding ends tokens at once.

## Rate limits and failure behavior

Both endpoints count against the per-source budget (`RATE_CONNECT_PER_MIN`, default 600) and the per-device budget in the RateLimit DO (`RATE_CONNECT_DEVICE_PER_MIN`, default 30, one budget for challenge and token requests together). A limiter that fails refuses (429). On the daemon: the tunnel client asks for a fresh `connect` token before every connection attempt; a rate limit or network error retries with the tunnel's jittered backoff; a refusal (401/403) stops the tunnel and the supervisor retries with its own backoff (up to 5 minutes), so a revoked device does not hammer the gateway; a daemon with no recorded binding waits (no gateway call) until enrollment records one.

## What this does not cover

- A live tunnel socket is not closed when its device is revoked afterwards; the revoked device gets no new token and no new connection, and the signed revocation list is what peers enforce (G4). Closing sockets belongs with the offboarding cascade.
- The root public key at the gateway is the admin's registration, a gateway-side copy: a malicious gateway can register its own and let in devices the real root never approved. Such a device still cannot read or forge task content, because peers verify bindings against the pinned root. The token only gates which sockets and requests the gateway serves.
- Anyone who asks for challenges for a device can fill its 4 outstanding slots and make the device's own pending challenge fail once; the device retries. The per-device rate limit bounds how often.
- Tokens are bearer credentials: whoever holds one can use it until it expires (a `connect` token once). They are in no log or stored record (the canary test scans for the secrets).
