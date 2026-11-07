#!/bin/sh
# Copyright 2026 The Parley Authors
# SPDX-License-Identifier: Apache-2.0
#
# Publish the Homebrew formula of a release to the project's tap.
#   scripts/publish-tap.sh <dist-dir> <tap-checkout> [--dry-run]
# <dist-dir> is a release directory made by scripts/release.sh (signed) or downloaded from the GitHub release;
# <tap-checkout> is a git checkout of the tap repository (kalahroudi/homebrew-parley). Nothing is trusted before it
# is verified: the SHA256SUMS signature must verify against the project key (release/release.pub, or the file named by
# PARLEY_RELEASE_PUB for tests), every file it lists must match, parley.rb must be one of them, and its version must be
# the one the signature names. Then Formula/parley.rb is committed and pushed. --dry-run does the verification and
# says what it would do, without touching the checkout.
# No credentials are read or stored here: pushing uses whatever the checkout's git remote already has (a credential
# helper or deploy key set up by the person or job that runs this). PARLEY_RELEASE_TOOL names a built parley-release.
set -eu

usage() {
	echo "usage: $0 <dist-dir> <tap-checkout> [--dry-run]" >&2
	exit 2
}
fail() {
	echo "publish-tap.sh: $*" >&2
	exit 1
}

[ $# -ge 2 ] && [ $# -le 3 ] || usage
dist=$1
tap=$2
dry=0
case ${3:-} in
'') ;;
--dry-run) dry=1 ;;
*) usage ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
pub=${PARLEY_RELEASE_PUB:-$root/release/release.pub}
tool=${PARLEY_RELEASE_TOOL:-}
if [ -z "$tool" ]; then
	tooldir=$(mktemp -d)
	trap 'rm -rf "$tooldir"' EXIT
	tool=$tooldir/parley-release
	(cd "$root" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$tool" ./cmd/parley-release)
fi

[ -f "$dist/SHA256SUMS" ] && [ -f "$dist/SHA256SUMS.minisig" ] || fail "$dist has no signed SHA256SUMS"
signed=$("$tool" verify "$pub" "$dist/SHA256SUMS") || fail "SHA256SUMS is not signed by the project key"
"$tool" verify-checksums "$dist/SHA256SUMS" || fail "a file does not match SHA256SUMS"
grep -q '  parley.rb$' "$dist/SHA256SUMS" || fail "parley.rb is not covered by SHA256SUMS"
tag=$(printf '%s\n' "$signed" | sed -n 's/^signature ok: parley release \(v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\) issued=.*/\1/p')
[ -n "$tag" ] || fail "the signature names no release version"
grep -q "^  version \"${tag#v}\"\$" "$dist/parley.rb" || fail "parley.rb is not the formula of $tag"
[ -d "$tap/.git" ] || fail "$tap is not a git checkout"

if [ "$dry" = 1 ]; then
	echo "dry run: would publish parley $tag to $tap (Formula/parley.rb), commit \"parley $tag\" and push; nothing was changed"
	exit 0
fi
mkdir -p "$tap/Formula"
cp "$dist/parley.rb" "$tap/Formula/parley.rb"
git -C "$tap" add Formula/parley.rb
if git -C "$tap" diff --cached --quiet; then
	echo "parley $tag is already in the tap"
	exit 0
fi
git -C "$tap" -c "user.name=${PARLEY_GIT_NAME:-parley release}" -c "user.email=${PARLEY_GIT_EMAIL:-noreply@github.com}" commit -q -m "parley $tag"
git -C "$tap" push -q
echo "published parley $tag to the tap"
