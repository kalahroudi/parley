#!/bin/sh
# Copyright 2026 The Parley Authors
# SPDX-License-Identifier: Apache-2.0
#
# Publish the Debian packages of a release to the project's apt repository.
#   scripts/publish-apt.sh <dist-dir> <repo-checkout> [--dry-run]
# <dist-dir> is a release directory made by scripts/release.sh or downloaded from the GitHub release; <repo-checkout>
# is a git checkout of the branch that serves the repository (for example gh-pages); the repository is its apt/ folder:
# the .deb files of every release, Packages, Release, the signatures InRelease and Release.gpg, and parley.asc, the
# project key as an OpenPGP key for `signed-by`.
# Nothing is trusted before it is verified: SHA256SUMS must be signed by the project key (release/release.pub, or the
# file named by PARLEY_RELEASE_PUB for tests), every file it lists must match, and each .deb must be one of them. The
# index is then signed with the SAME project key (parley-release apt-sign), read from the encrypted key file named by
# PARLEY_RELEASE_KEY with its password in PARLEY_RELEASE_KEY_PASSWORD (environment only: neither is stored anywhere).
# The result depends only on the verified release, so publishing twice changes nothing.
# --dry-run verifies and prepares everything in a temporary copy (signing too, when the key is given) and says what it
# would do, without touching the checkout. Pushing uses the checkout's own git credentials.
set -eu

usage() {
	echo "usage: $0 <dist-dir> <repo-checkout> [--dry-run]" >&2
	exit 2
}
fail() {
	echo "publish-apt.sh: $*" >&2
	exit 1
}

[ $# -ge 2 ] && [ $# -le 3 ] || usage
dist=$1
repo=$2
dry=0
case ${3:-} in
'') ;;
--dry-run) dry=1 ;;
*) usage ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
pub=${PARLEY_RELEASE_PUB:-$root/release/release.pub}
key=${PARLEY_RELEASE_KEY:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tool=${PARLEY_RELEASE_TOOL:-}
if [ -z "$tool" ]; then
	tool=$work/parley-release
	(cd "$root" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$tool" ./cmd/parley-release)
fi

[ -f "$dist/SHA256SUMS" ] && [ -f "$dist/SHA256SUMS.minisig" ] || fail "$dist has no signed SHA256SUMS"
signed=$("$tool" verify "$pub" "$dist/SHA256SUMS") || fail "SHA256SUMS is not signed by the project key"
"$tool" verify-checksums "$dist/SHA256SUMS" || fail "a file does not match SHA256SUMS"
tag=$(printf '%s\n' "$signed" | sed -n 's/^signature ok: parley release \(v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\) issued=.*/\1/p')
issued=$(printf '%s\n' "$signed" | sed -n 's/^.* issued=\([0-9][0-9]*\) expires=.*/\1/p')
[ -n "$tag" ] && [ -n "$issued" ] || fail "the signature names no release version"
debs=""
for arch in amd64 arm64; do
	f=parley_${tag#v}_${arch}.deb
	[ -f "$dist/$f" ] || fail "$f is missing from $dist"
	grep -q "  $f\$" "$dist/SHA256SUMS" || fail "$f is not covered by SHA256SUMS"
	debs="$debs $f"
done
[ -d "$repo/.git" ] || fail "$repo is not a git checkout"
if [ -n "$key" ]; then
	[ -f "$key" ] || fail "PARLEY_RELEASE_KEY names no file"
	[ -n "${PARLEY_RELEASE_KEY_PASSWORD:-}" ] || fail "set PARLEY_RELEASE_KEY_PASSWORD to the release key's password"
elif [ "$dry" = 0 ]; then
	fail "set PARLEY_RELEASE_KEY to the encrypted release key file to sign the repository"
fi

# Build the repository in a scratch directory first: what is there plus this release.
apt=$work/apt
mkdir -p "$apt"
if [ -d "$repo/apt" ]; then
	cp "$repo"/apt/parley_*.deb "$apt"/ 2>/dev/null || true
fi
for f in $debs; do cp "$dist/$f" "$apt/$f"; done
"$tool" apt "$apt" "$issued"
if [ -n "$key" ]; then
	"$tool" apt-sign "$key" "$apt"
	"$tool" apt-key "$key" "$apt/parley.asc" >/dev/null
fi

if [ "$dry" = 1 ]; then
	if [ -n "$key" ]; then signing="signed with the project key"; else signing="not signed (no PARLEY_RELEASE_KEY)"; fi
	echo "dry run: would publish parley $tag to $repo/apt ($(ls "$apt" | wc -l | tr -d ' ') files, $signing), commit \"apt: parley $tag\" and push; nothing was changed"
	exit 0
fi
mkdir -p "$repo/apt"
cp "$apt"/* "$repo/apt/"
git -C "$repo" add apt
if git -C "$repo" diff --cached --quiet; then
	echo "parley $tag is already in the apt repository"
	exit 0
fi
git -C "$repo" -c "user.name=${PARLEY_GIT_NAME:-parley release}" -c "user.email=${PARLEY_GIT_EMAIL:-noreply@github.com}" commit -q -m "apt: parley $tag"
git -C "$repo" push -q
echo "published parley $tag to the apt repository"
