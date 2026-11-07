# Self-update

**Status: updater building blocks, not yet wired, not enabled.** `internal/update` is library code only. Nothing in
`parleyd` or `parley-cli` calls it, so no installed program updates itself today. What is still owed is listed at the
end of this page.

Releases are signed with the project's own Ed25519 key (minisign format). Its public half is `release/release.pub`
and is compiled into the binaries (`release/key.go`); nothing fetched at run time can replace it.

`internal/update` installs a release only when all of this holds:

1. `SHA256SUMS` and `SHA256SUMS.minisig` verify against the pinned key. Another key, or the same key id with
   different key material, is refused.
2. The signed comment is exactly `parley release vMAJOR.MINOR.PATCH`. It ties the checksums to one version, so an
   old signed release cannot be served as a new one; binaries are fetched from that version's own address.
3. The version is newer than the running one. It never goes back, unless an operator pins that exact older version.
4. Each downloaded binary matches its checksum in the signed file. `parleyd` and `parley-cli` are replaced together
   or not at all; the old file is renamed aside first, which also works for a running program on Windows.

The transport (GitHub, a mirror) is untrusted: downloads are size-limited and redirects must stay on https. Source
and `go install` builds have no release version and are never replaced; files owned by a package manager
(`/usr/bin`, Homebrew's Cellar, Nix, Snap) are left to it (`update.Locate`).

**Not done yet (tracked by `TestPending_T504WiringAndChannels`):** the daemon's background check, `parley-cli
update`, the Homebrew formula and tap, the Debian package and apt repository. The new version would run from the
next start: the updater does not restart a process.
The release comment carries no expiry yet, and the updater does not yet check that it runs as the owner of the install
directory; both, and an operator opt-out, are owed by the wiring above. An attacker who blocks the network can keep a device on an old
version; the gateway's protocol-version check bounds that.
