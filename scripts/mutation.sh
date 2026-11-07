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
# fails on every mutant that lived or was not covered (a timed-out one is detected), unless
# tests/coverage/mutation-allowlist.json names it with a reason. Nothing is
# silent, and a stale entry fails a full run. TypeScript: stryker.config.json
# breaks below 100 with no mutant excluded, and a runner error (a mutant whose
# run crashes) is a failure too, because Stryker leaves it out of the score.
#
#   scripts/mutation.sh                 # everything (main, nightly, local)
#   MUTATION_SCOPE=changed BASE=origin/main scripts/mutation.sh
#                                       # only tier 1 packages and files changed
#                                       # since BASE (pull requests)
#   MUTATION_PART=ts | go:0/4 ...       # only a part of the selected work (see mutation-scope.mjs), so
#                                       # that CI can run the parts as jobs of their own
set -eu
cd "$(dirname "$0")/.."
scope=${MUTATION_SCOPE:-all}
base=${BASE:-origin/main}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT INT TERM

# The scope is chosen by scripts/mutation-scope.mjs, which fails closed: when it cannot
# prove what changed, it returns everything.
node scripts/mutation-scope.mjs "$scope" "$base" "${MUTATION_PART:-}" > "$out/scope.json" || exit 2
scope=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).scope' "$out/scope.json")
pkgs=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).packages.join(" ")' "$out/scope.json")
mutate=$(node -p 'JSON.parse(require("fs").readFileSync(process.argv[1])).files.map((f) => f.replace(/^gateway\//, "")).join(" ")' "$out/scope.json")
stale=--stale
[ "$scope" = all ] || stale=
# A mutant is given this many times the normal test time before it counts as timed out (detected, see
# scripts/mutation-gate.mjs). A mutant that survives runs at normal speed, so a pull request can use a
# small factor and finish fast; the full run keeps a wide margin for slow runners.
coef=${MUTATION_TIMEOUT_COEFFICIENT:-20}
[ "$scope" = all ] || coef=${MUTATION_TIMEOUT_COEFFICIENT:-8}
status=0
for p in $pkgs; do
	echo "== mutation: $p"
	json="$out/$(echo "$p" | tr / _).json"
	go run github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0 unleash \
		--workers 2 --timeout-coefficient "$coef" \
		--invert-assignments --invert-bitwise --invert-bwassign --invert-logical \
		--invert-loopctrl --remove-self-assignments -o "$json" "./$p" > "$out/gremlins.log" 2>&1 || status=1
	cat "$out/gremlins.log"
	# A package with no mutable code (a single embed and copy, such as release) makes gremlins print this and
	# write no file. That is an empty result; any other missing file stays a failure for the gate to report.
	if [ ! -e "$json" ] && grep -q '^No results to report' "$out/gremlins.log"; then
		echo '{"files":[]}' > "$json"
	fi
	node scripts/mutation-gate.mjs "$p" "$json" $stale || status=1
done

# Tier 1 TypeScript. Needs `npm ci` in gateway first. Linux only: it is platform independent, so the
# other OSes (which run this for their own Go files) set MUTATION_TS=0.
if [ "${MUTATION_TS:-1}" = 0 ]; then
	echo "== mutation: gateway tier 1 files (skipped on this OS)"
elif [ -z "$mutate" ]; then
	echo "== mutation: gateway tier 1 files (none affected by this change)"
else
	echo "== mutation: gateway tier 1 files:$mutate"
	# One comma-separated --mutate: Stryker keeps only the last of repeated --mutate flags, which would
	# mutate one file and report the rest as clean.
	list=$(printf '%s' "$mutate" | tr ' ' ',')
	(cd gateway && npx stryker run --mutate "$list") || status=1
	# shellcheck disable=SC2086
	node scripts/stryker-gate.mjs gateway/reports/mutation/mutation.json $mutate || status=1
fi
exit $status
