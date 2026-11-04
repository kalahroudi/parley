#!/bin/sh
# Copyright 2026 The Parley Authors
# SPDX-License-Identifier: Apache-2.0

# Mutation testing for the tier 1 Go packages (tests/coverage/tiers.json) with
# gremlins. Efficacy is killed / (killed + lived); timed-out and uncovered
# mutants are not counted, so both are listed rather than hidden.
#
# The 95% floor exists for equivalent mutants that no test can tell apart from
# the original, such as skipping the directory fsync that makes a rename durable
# (syncDir in internal/binding and internal/revocation: os.File methods on a nil
# file return an error, so the failure path looks the same). Any other survivor
# is a missing test: fix the test, do not lower the floor.
set -eu
cd "$(dirname "$0")/.."
pkgs=$(node -e 'console.log(require("./tests/coverage/tiers.json").tiers["1"].packages.join(" "))')
status=0
for p in $pkgs; do
	echo "== mutation: $p"
	go run github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0 unleash \
		--threshold-efficacy 95 --workers 2 --timeout-coefficient 20 "./$p" || status=1
done

# Tier 1 TypeScript (tests/coverage/gateway-tier1.json): the same bar, with Stryker.
# Every mutant must be killed (stryker.config.json breaks below 100). Needs
# `npm ci` in gateway first.
echo "== mutation: gateway tier 1 files"
(cd gateway && npm run test:mutation) || status=1
# Errored and ignored mutants do not count against Stryker's threshold; this gate does.
node scripts/stryker-gate.mjs || status=1
exit $status
