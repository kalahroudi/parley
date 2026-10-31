#!/bin/sh
# Copyright 2026 The Parley Authors
# SPDX-License-Identifier: Apache-2.0
#
# One-time release key setup.
#   scripts/release-setup.sh [--no-commit]
# 1. Generates the release key pair with parley-release keygen. The password is
#    PARLEY_RELEASE_KEY_PASSWORD if set, otherwise a random one.
# 2. Stores the encrypted key as the PARLEY_RELEASE_KEY repo secret and the
#    password as PARLEY_RELEASE_KEY_PASSWORD, using the gh CLI (GH_REPO selects
#    the repository; default is the current checkout's).
# 3. Writes the public key to release/release.pub and commits it (not pushed).
# The secret key, password and a copy of the public key are kept in
# $PARLEY_KEY_DIR (default ~/.parley-release, mode 0700) - back that up
# offline. Nothing secret is written inside the repository or printed.
# It refuses to run if the key directory or either secret already exists.
set -eu

commit=1
[ "${1:-}" = --no-commit ] && commit=0

root=$(cd "$(dirname "$0")/.." && pwd)
keydir=${PARLEY_KEY_DIR:-$HOME/.parley-release}
pubout=${PARLEY_PUB_OUT:-release/release.pub}

if [ -e "$keydir" ]; then
	echo "release-setup.sh: $keydir already exists; refusing to overwrite a release key" >&2
	exit 1
fi
if gh secret list | grep -qE '^PARLEY_RELEASE_KEY(_PASSWORD)?[[:space:]]'; then
	echo "release-setup.sh: release secrets already exist in the repository" >&2
	exit 1
fi

umask 077
mkdir -p "$keydir"
password=${PARLEY_RELEASE_KEY_PASSWORD:-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')}
printf '%s\n' "$password" >"$keydir/release.password"

cd "$root"
tool=$keydir/parley-release
go build -trimpath -o "$tool" ./cmd/parley-release
PARLEY_RELEASE_KEY_PASSWORD=$password "$tool" keygen "$keydir/release.key" "$keydir/release.pub"
rm -f "$tool"

gh secret set PARLEY_RELEASE_KEY <"$keydir/release.key"
printf '%s' "$password" | gh secret set PARLEY_RELEASE_KEY_PASSWORD

mkdir -p "$(dirname "$pubout")"
cp "$keydir/release.pub" "$pubout"
if [ "$commit" = 1 ]; then
	git add "$pubout"
	git commit -m "Add release public key" -- "$pubout"
fi
echo "release key set up; secret key and password are in $keydir (back them up offline)"
