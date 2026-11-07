# Self-update

**Status:** `parleyd` checks for updates in the background and `parley-cli update` checks and applies them, both
through `internal/update`. What is still owed is at the end of this page.

Releases are signed with the project's own Ed25519 key (minisign format). Its public half is `release/release.pub`
and is compiled into the binaries (`release/key.go`); nothing fetched at run time can replace it.

`internal/update` installs a release only when all of this holds:

1. `SHA256SUMS` and `SHA256SUMS.minisig` verify against the pinned key. Another key, or the same key id with
   different key material, is refused.
2. The signed comment is exactly `parley release vMAJOR.MINOR.PATCH issued=<unix> expires=<unix>`. It ties the
   checksums to one version, so an old signed release cannot be served as a new one, and to a validity window: a
   manifest that has expired, was issued in the future (more than 5 minutes ahead), or claims more than 400 days is
   refused, so a mirror that freezes the feed is noticed when the manifest it replays expires. `scripts/release.sh`
   writes the window (`PARLEY_VALID_DAYS`, default 180); the project must re-sign before it ends. Binaries are
   fetched from that version's own address.
3. The version is newer than the running one. It never goes back, unless an operator pins that exact older version.
4. Each downloaded binary matches its checksum in the signed file. `parleyd` and `parley-cli` are replaced together
   or not at all; the old file is renamed aside first, which also works for a running program on Windows.

**Install directory.** Before it downloads anything the updater checks the place it would write to
(`internal/update/owner.go`): the directory is owned by the user running the update and not writable by group or
others, each parent is owned by that user or the system and none is world-writable (unless sticky, like `/tmp`), and
each program is a regular file (not a link) owned by that user and not group- or world-writable. Otherwise it
replaces nothing and says `ErrNotOwner`. Because it is the *effective* user that counts, a root process refuses a
user's directory and a user process refuses root's: an update never runs as another user than the install belongs
to. On Windows only ownership is checked (by the user, or the owner new files get, for the directory and programs;
the system for parents); ACLs are not read.

The transport (GitHub, a mirror) is untrusted: downloads are size-limited and redirects must stay on https. Source
and `go install` builds have no release version and are never replaced; files owned by a package manager
(`/usr/bin`, Homebrew's Cellar, Nix, Snap) are left to it (`update.Locate`).

## Configuration (operator opt-out and pin)

In `config.json` (read by `parleyd` and `parley-cli`), all optional:

```json
"update": { "mode": "auto", "pin": "v1.4.2", "interval": "6h", "source": "https://mirror.example/parley/releases" }
```

- `mode`: `auto` (default: check and install a verified newer release), `check` (check and record what is
  available, install only on `parley-cli update`) or `off` (never contact the release source).
- `pin`: hold the device on exactly that version. It is installed even if older (that is what pinning is for), and no
  other version ever is.
- `interval`: 1h to 168h, default 6h.
- `source`: a mirror with GitHub's release layout, https only (loopback http for tests). Releases from a mirror are
  verified exactly like the project's own, so a mirror can withhold an update but never forge one.

The environment variable `PARLEY_UPDATE` (`auto`, `check` or `off`) lets an operator restrict updates from a service
unit or container without editing the file. It only tightens: `off` beats everything, `check` beats `auto`, and
it can never turn on what the configuration turned off. A value it does not understand means `off`.

## Running updates

- **The daemon** (`mode` auto or check) runs a cycle shortly after start (a random delay up to 5 minutes) and then
  every `interval`. In `auto` it installs a verified newer release; in `check` it only records that one exists. The
  new version is on disk and runs from the next start of `parleyd`: the daemon does not own the service manager,
  so the log says "update installed; restart parleyd to run it". Logs carry the component, a version
  (`v1-2-3`) and a fixed reason code; never a URL, path or message from the network. The last cycle is recorded in
  `update-status.json` in the state directory (state, versions, reason code).
- **`parley-cli update status`** prints the version, the policy (mode, pin, mirror) and the last recorded cycle.
  **`check`** verifies the signed feed and reports what is available; **`apply`** installs a verified newer release;
  `-version vX.Y.Z` selects exactly one version (older included, as a pin does). `off` (file or environment)
  refuses `check` and `apply` before anything is built or contacted. A `config.json` that exists but is invalid stops
  the command, so a broken file never silently drops a pin or an opt-out.
- **Nothing is installed before verification.** The install step only accepts the release object that the check
  returns after the signature, expiry, version and checksum checks.
- **Restart safety.** Before swapping, the updater writes a journal naming the programs. If the process is killed
  or the machine loses power in the middle, the next cycle (daemon or CLI) puts every program that has a `.old`
  file beside it back, so the two programs are the same old version again, and tries again later; staged downloads
  are deleted. The daemon and `parley-cli` hold a lock in the state directory, so they never swap at once.
- **A running program is replaced** by renaming it aside first, which works on Windows (a running `.exe` cannot be
  overwritten or deleted but can be renamed); the process keeps running the old file, and the leftover `.old` is
  removed by a later cycle once it has exited.
- **Never as another user.** See the install directory rules above; the effective user must own the install.

**Not done yet (tracked by `TestPending_T504WiringAndChannels`):** the Homebrew tap and the apt repository as
scripted publishing steps, the JJ-01 journey (T509) and the fresh-machine checks (T511). An attacker who blocks the
network can keep a device on an old version until the last manifest it saw expires; the gateway's protocol-version
check bounds that too.
