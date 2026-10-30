.PHONY: test test-layout test-go

test: test-layout test-go

test-layout:
	node --test tests/

test-go:
	@if command -v go >/dev/null; then go vet ./... && go test -race ./...; else echo "go not installed, skipping"; fi
