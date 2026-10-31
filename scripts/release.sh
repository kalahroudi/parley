#!/bin/sh
# Copyright 2026 The Parley Authors
# SPDX-License-Identifier: Apache-2.0
#
# Reproducible release build.
#   scripts/release.sh <version> <outdir> [secret-key-file]
# Builds parleyd and parley-cli for every target, writes SHA256SUMS and
# sbom.cdx.json, and (when a secret key file is given) signs SHA256SUMS with
# the project's own Ed25519 key, producing SHA256SUMS.minisig.
# PARLEY_TARGETS overrides the target list (space-separated os/arch).
set -eu

version=${1:?version}
out=${2:?outdir}
key=${3:-}
targets=${PARLEY_TARGETS:-"linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"}

root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
cd "$root"

# Fixed environment: no cgo, no VCS stamping, no local paths, no build id.
export CGO_ENABLED=0 GOFLAGS=-mod=readonly TZ=UTC
tool=$(mktemp -d)/parley-release
go build -trimpath -buildvcs=false -o "$tool" ./cmd/parley-release

files=""
bins=""
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
		bins="$bins $out/$name"
	done
done

# shellcheck disable=SC2086
"$tool" sbom "$version" "$out/sbom.cdx.json" $bins
# shellcheck disable=SC2086
"$tool" checksums "$out" "$out/SHA256SUMS" $files sbom.cdx.json
if [ -n "$key" ]; then
	"$tool" sign "$key" "$out/SHA256SUMS" "parley release $version"
fi
