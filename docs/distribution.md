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

**Install directory.** Before it downloads anything the updater resolves links in the directory and checks the place it
would write to (`internal/update/owner.go`): the directory is owned by the user running the update and not writable by
group or others, each parent is owned by that user or the system and none is writable by everyone (or by a group, unless
the system owns it, like `/Library` on macOS) unless sticky, like `/tmp`, and each program is a regular file (not a
link) owned by that user, not group- or world-writable, and not setuid or setgid. Otherwise it replaces nothing and says
`ErrNotOwner`. The downloads go into the resolved directory, and the same check runs again right before the swap, so a
link or file changed in between stops the update with nothing replaced. Because it is the *effective* user that counts,
a root process refuses a user's directory and a user process refuses root's: an update never runs as another user than
the install belongs to. A directory under Homebrew, Nix, snap, `/usr/bin`, `Program Files` or `WindowsApps` is refused
with `ErrManaged`, which says to update with the package manager or installer. On Windows ownership is checked as
above, and the access list of the directory, its programs and each parent is read: an allow entry for Everyone, Users or
Authenticated Users that writes (parents: deletes entries or changes permissions) refuses the update; what the system owns (such as `C:\`) keeps the access list the system gave it. What remains is a
process of the same user (or root) racing the swap, which already owns the programs.

The transport (GitHub, a mirror) is untrusted: downloads are size-limited and redirects must stay on https. Source
and `go install` builds have no release version and are never replaced; files owned by a package manager
(`/usr/bin`, Homebrew's Cellar, Nix, Snap) are left to it (`update.Locate`).

**Not done yet (tracked by `TestPending_T504WiringAndChannels`):** the daemon's background check, `parley-cli
update`, the Homebrew formula and tap, the Debian package and apt repository. The new version would run from the
next start: the updater does not restart a process.
There is no operator opt-out yet; it is owed by the wiring above. An attacker who blocks the network can keep a device on an old version until
the last manifest it saw expires; the gateway's protocol-version check bounds that too.
