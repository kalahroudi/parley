.PHONY: test test-layout test-go test-gateway soak dev

test: test-layout test-go test-gateway

test-gateway:
	cd gateway && npm ci && npm run typecheck && npm test

# T108: the 10k-message reconnect soak. Slow (about 10s on Linux/macOS, minutes on
# Windows), so it is not part of `make test`; CI runs it as its own step.
soak:
	cd gateway && npm ci && npm run test:soak

test-layout:
	node --test "tests/**/*.test.mjs"

# Skips when Go is missing locally, but fails under CI (CI is set by GitHub
# Actions and most other CI systems) so a missing toolchain can't pass silently.
test-go:
	@if command -v go >/dev/null; then go vet ./... && go test -race ./...; \
	elif [ -n "$$CI" ]; then echo "go not installed in CI" >&2; exit 1; \
	else echo "go not installed, skipping"; fi

# Boot the gateway, a mock OIDC server and N daemons (default 2): make dev N=3
dev:
	node tests/harness/harness.mjs --daemons=$(or $(N),2)
