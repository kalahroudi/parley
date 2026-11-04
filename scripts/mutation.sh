#!/bin/sh
# Copyright 2026 The Parley Authors
# SPDX-License-Identifier: Apache-2.0

# Mutation testing for the tier 1 code: the Go packages in tests/coverage/tiers.json
# with gremlins, and the TypeScript files in tests/coverage/gateway-tier1.json with
# Stryker. Both must kill every mutant.
#
# Go: every gremlins mutator is on (arithmetic, boundary, negation, increment,
# negatives and also assignments, bitwise, logical, loop control, self-assignment).
# Gremlins only counts killed / (killed + lived) and leaves mutants that no test
# reaches out of the score, so the score is not used: scripts/mutation-gate.mjs
# fails on every mutant that lived, timed out or was not covered, unless
# tests/coverage/mutation-allowlist.json names it with a reason. Nothing is
# silent, and a stale entry fails a full run. TypeScript: stryker.config.json
# breaks below 100 with no mutant excluded, and a runner error (a mutant whose
# run crashes) is a failure too, because Stryker leaves it out of the score.
#
#   scripts/mutation.sh                 # everything (main, nightly, local)
#   MUTATION_SCOPE=changed BASE=origin/main scripts/mutation.sh
#                                       # only tier 1 packages and files changed
#                                       # since BASE (pull requests)
set -eu
cd "$(dirname "$0")/.."
scope=${MUTATION_SCOPE:-all}
base=${BASE:-origin/main}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT INT TERM

changed=
if [ "$scope" = changed ]; then
	changed=$(git diff --name-only "$base"...HEAD)
	# A change to the gates themselves can weaken every package: run them all.
	if echo "$changed" | grep -Eq '^(go\.mod|tests/coverage/|scripts/mutation|\.github/workflows/ci\.yml|gateway/(stryker\.config\.json|vitest\.(mutation\.)?config\.ts|package-lock\.json))'; then
		scope=all
	fi
elif [ "$scope" != all ]; then
	echo "MUTATION_SCOPE must be all or changed" >&2
	exit 2
fi

stale=--stale
[ "$scope" = all ] || stale=
pkgs=$(node -e 'console.log(require("./tests/coverage/tiers.json").tiers["1"].packages.join(" "))')
status=0
for p in $pkgs; do
	if [ "$scope" = changed ] && ! echo "$changed" | grep -q "^$p/"; then
		echo "== mutation: $p (unchanged, skipped)"
		continue
	fi
	echo "== mutation: $p"
	json="$out/$(echo "$p" | tr / _).json"
	go run github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0 unleash \
		--workers 2 --timeout-coefficient 20 \
		--invert-assignments --invert-bitwise --invert-bwassign --invert-logical \
		--invert-loopctrl --remove-self-assignments -o "$json" "./$p" || status=1
	node scripts/mutation-gate.mjs "$p" "$json" $stale || status=1
done

# Tier 1 TypeScript. Needs `npm ci` in gateway first.
ts=$(node -e 'console.log(require("./tests/coverage/gateway-tier1.json").files.map((f) => f.replace(/^gateway\//, "")).join(" "))')
mutate=
if [ "$scope" = all ]; then
	mutate=$ts
else
	for f in $ts; do
		t=$(basename "$f" .ts)
		# A changed file, or a changed test of it.
		if echo "$changed" | grep -Eq "^gateway/(src/$t\.ts|test/$t\.test\.ts|test/wire\.ts)\$"; then mutate="$mutate $f"; fi
	done
fi
if [ -z "$mutate" ]; then
	echo "== mutation: gateway tier 1 files (unchanged, skipped)"
else
	echo "== mutation: gateway tier 1 files:$mutate"
	args=
	for f in $mutate; do args="$args --mutate $f"; done
	# shellcheck disable=SC2086
	(cd gateway && npx stryker run $args) || status=1
	node scripts/stryker-gate.mjs gateway/reports/mutation/mutation.json || status=1
fi
exit $status
