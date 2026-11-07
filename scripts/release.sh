#!/bin/sh
# Copyright 2026 The Parley Authors
# SPDX-License-Identifier: Apache-2.0
#
# Reproducible release build.
#   scripts/release.sh <version> <outdir> [secret-key-file]
# Builds parleyd and parley-cli for every target, writes SHA256SUMS and
# sbom.cdx.json, and (when a secret key file is given) signs SHA256SUMS with
# the project's own Ed25519 key, producing SHA256SUMS.minisig.
# The key file is encrypted; its password comes from PARLEY_RELEASE_KEY_PASSWORD.
# <outdir> must be empty or absent so stale files can never be published.
# PARLEY_VALID_DAYS (default 180, at most 400) is how long the signed manifest stays valid: after that daemons
# refuse it, so the project re-signs (re-runs the release signing) before then. PARLEY_ISSUED (unix seconds)
# fixes the issue time for tests.
# PARLEY_TARGETS overrides the target list (space-separated os/arch).
# Builds are reproducible for a given Go toolchain; the toolchain version is
# recorded in the SBOM. Set PARLEY_GO_VERSION (go.mod's toolchain line, currently go1.27.3) to fail unless the
# toolchain matches exactly. GOFLAGS is overridden with -mod=readonly.
set -eu

version=${1:?version}
out=${2:?outdir}
key=${3:-}
targets=${PARLEY_TARGETS:-"linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"}

root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
if [ -n "$(ls -A "$out")" ]; then
	echo "release.sh: $out is not empty" >&2
	exit 1
fi
if [ -n "${PARLEY_GO_VERSION:-}" ]; then
	have=$(go env GOVERSION)
	if [ "$have" != "$PARLEY_GO_VERSION" ]; then
		echo "release.sh: toolchain $have, want $PARLEY_GO_VERSION" >&2
		exit 1
	fi
fi
days=${PARLEY_VALID_DAYS:-180}
case $days in
'' | *[!0-9]* | 0*)
	echo "release.sh: PARLEY_VALID_DAYS must be a number of days from 1 to 400" >&2
	exit 1
	;;
esac
if [ "$days" -gt 400 ]; then
	echo "release.sh: PARLEY_VALID_DAYS must be a number of days from 1 to 400" >&2
	exit 1
fi
# A relative key path must keep meaning the caller's directory.
case $key in
'' | /* | [A-Za-z]:*) ;;
*) key=$(pwd)/$key ;;
esac
cd "$root"

# Fixed environment: no cgo, no VCS stamping, no local paths, no build id.
export CGO_ENABLED=0 GOFLAGS=-mod=readonly
tooldir=$(mktemp -d)
trap 'rm -rf "$tooldir"' EXIT
tool=$tooldir/parley-release
go build -trimpath -buildvcs=false -o "$tool" ./cmd/parley-release

# Binary names contain no whitespace; everything after the build runs from
# inside $out with relative names, so a path with spaces in $out is harmless.
files=""
for t in $targets; do
	os=${t%/*}
	arch=${t#*/}
	ext=""
	[ "$os" = windows ] && ext=.exe
	for cmd in parleyd parley-cli; do
		name=${cmd}_${version}_${os}_${arch}${ext}
		GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
			-ldflags "-s -w -buildid= -X main.version=$version" \
			-o "$out/$name" "./cmd/$cmd"
		files="$files $name"
	done
done

cd "$out"
# shellcheck disable=SC2086
"$tool" sbom "$version" sbom.cdx.json $files
# shellcheck disable=SC2086
"$tool" checksums . SHA256SUMS $files sbom.cdx.json
if [ -n "$key" ]; then
	# The signed comment is the manifest header the updater enforces (internal/update/manifest.go): the version and
	# a validity window, so a frozen update feed shows up as an expired manifest.
	issued=${PARLEY_ISSUED:-$(date +%s)}
	"$tool" sign "$key" SHA256SUMS "parley release $version issued=$issued expires=$((issued + days * 86400))"
fi
