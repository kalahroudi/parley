.PHONY: test test-layout test-go dev

test: test-layout test-go

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
	N=$(or $(N),2) node tests/harness/harness.mjs
