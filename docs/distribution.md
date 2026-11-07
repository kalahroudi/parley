# Self-update

**Status: updater building blocks, not yet wired, not enabled.** `internal/update` is library code only. Nothing in
`parleyd` or `parley-cli` calls it, so no installed program updates itself today. What is still owed is listed at the
end of this page.

Releases are signed with the project's own Ed25519 key (minisign format). Its public half is `release/release.pub`
and is compiled into the binaries (`release/key.go`); nothing fetched at run time can replace it.

`internal/update` installs a release only when all of this holds:

1. `SHA256SUMS` and `SHA256SUMS.minisig` verify against the pinned key. Another key, or the same key id with
   different key material, is refused.
2. The signed comment is exactly `parley release vMAJOR.MINOR.PATCH issued=<unix> expires=<unix>`. It ties the
   checksums to one version, so an old signed release cannot be served as a new one, and to a validity window: a
   manifest that has expired, was issued in the future (more than 5 minutes ahead), or claims more than 400 days is
   refused (the 5 minutes of clock skew is allowed only on the issue time; expiry is strict, so a slow clock never
   stretches a manifest past what was signed), so a mirror that freezes the feed is noticed when the manifest it replays expires. `scripts/release.sh`
   writes the window (`PARLEY_VALID_DAYS`, default 180); the project must re-sign before it ends. Binaries are
   fetched from that version's own address.
3. The version is newer than the running one. It never goes back, unless an operator pins that exact older version.
4. Each downloaded binary matches its checksum in the signed file. `parleyd` and `parley-cli` are replaced together
   or not at all; the old file is renamed aside first, which also works for a running program on Windows.

The transport (GitHub, a mirror) is untrusted: downloads are size-limited and redirects must stay on https. Source
and `go install` builds have no release version and are never replaced; files owned by a package manager
(`/usr/bin`, Homebrew's Cellar, Nix, Snap) are left to it (`update.Locate`).

**Not done yet (tracked by `TestPending_T504WiringAndChannels`):** the daemon's background check, `parley-cli
update`, the Homebrew formula and tap, the Debian package and apt repository. The new version would run from the
next start: the updater does not restart a process.
The updater does not yet check that it runs as the owner of the install directory, and there is no operator opt-out
yet; both are owed by the wiring above. An attacker who blocks the network can keep a device on an old version until
the last manifest it saw expires; the gateway's protocol-version check bounds that too.
