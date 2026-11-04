# Message pipeline wire formats (internal/frames)

Every parser here reads bytes an attacker may control. Each is strict: unknown
or duplicate JSON keys (matched case-sensitively), non-canonical base64 (the
text must equal the re-encoding of its bytes), oversize values, trailing bytes
and unknown kinds are all errors. Sizes are checked before anything is allocated.

## Relay frames (JSON, via the gateway)

A daemon sends `to`; the gateway delivers the same frame with `from` in its
place. `nonce` is 1..32 bytes, `prekey` 1..1024 bytes, both standard padded
base64. `retry_after_ms` is at most 86400000.

<!-- vector:request -->
`{"t":"prekey_request","id":"r1","to":"dev-b","nonce":"AQID","expires_at":1800000900000}`
<!-- vector:reply -->
`{"t":"prekey_reply","id":"r1","to":"dev-a","prekey":"CQg="}`
<!-- vector:refuse -->
`{"t":"prekey_refused","id":"r1","to":"dev-a"}`

A refusal received from the gateway carries `reason` (`refused`, `offline` or
`rate_limited`) and optionally `retry_after_ms`.

## Prekey blob

`EncodePrekey`: the signed encoding of the prekey followed by its 64-byte
signature. Every field is a 4-byte big-endian length then the bytes, or a
8-byte big-endian integer. A blob is accepted only if re-encoding it gives the
same bytes. At most 1024 bytes.

## Inner plaintext (before padding and sealing)

One flag byte, `0` or `1`. With `0` the content follows. With `1` a 4-byte
big-endian length and that many bytes of prekey blob follow, then the content.

<!-- vector:inner -->
`006869` is flag 0 and content `hi`.
