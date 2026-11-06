.PHONY: m1 queued-ttl fuzz-smoke fuzz-long malgw-mutations test test-layout test-go test-gateway soak coverage mutation dev

test: test-layout test-go test-gateway

test-gateway:
	cd gateway && npm ci && npm run typecheck && npm test

# T108: the 10k-message reconnect soak. Slow (about 10s on Linux/macOS, minutes on
# Windows), so it is not part of `make test`; CI runs it as its own step.
soak:
	cd gateway && npm ci && npm run test:soak

# Coverage tiers from the plan (tests/coverage/tiers.json): tier 1 at 100%, tier 2
# at 95% line and 90% branch, tier 3 at 85%. Go reports statement coverage only,
# so Go branches are held by `make mutation`. The gateway gates cover the Durable
# Objects and handlers (vitest, istanbul) and the OIDC modules (node:test), per file.
coverage:
	go test -race -coverprofile=cover.out ./...
	go run ./scripts/covergate -profile cover.out
	cd gateway && npm ci && npm run test:coverage && npm run test:oidc-coverage

# Mutation testing of the tier 1 Go packages and gateway files (slow: minutes; run
# `cd gateway && npm ci` once first).
mutation:
	scripts/mutation.sh

test-layout:
	node --test "tests/**/*.test.mjs"

# Skips when Go is missing locally, but fails under CI (CI is set by GitHub
# Actions and most other CI systems) so a missing toolchain can't pass silently.
test-go:
	@if command -v go >/dev/null; then go vet ./... && go test -race ./...; \
	elif [ -n "$$CI" ]; then echo "go not installed in CI" >&2; exit 1; \
	else echo "go not installed, skipping"; fi

# Milestone M1 (T414), the one command: builds parleyd and parley-cli, runs the real gateway (wrangler dev) and
# three real daemons, and checks `parley-cli test` end to end (needs Go, Node and `cd gateway && npm ci`).
m1:
	node --test tests/m1-echo.test.mjs

# T405: Queued retention with a real daemon whose connection drops. The shortest tenant TTL is 15 minutes, so this takes
# about 17 (macOS and Linux; needs Go, Node and `cd gateway && npm ci`). Not part of `make test`; the Queued TTL workflow runs it.
queued-ttl:
	node --test tests/slow/queued-ttl.mjs

# Boot the gateway, a mock OIDC server and N daemons (default 2): make dev N=3
dev:
	node tests/harness/harness.mjs --daemons=$(or $(N),2)

# Proof that the T206 malicious-gateway tests fail when each defence is removed.
malgw-mutations:
	scripts/malgw-mutations.sh

# T207: every fuzz target for a few seconds (what CI runs on every push, on all OSes).
fuzz-smoke:
	node scripts/fuzz.mjs smoke

# T207: every fuzz target for FUZZTIME each (default 10m, so about 1 h 45 min for
# the ten targets). The weekly "Fuzz (long)" workflow runs this too.
fuzz-long:
	node scripts/fuzz.mjs long
