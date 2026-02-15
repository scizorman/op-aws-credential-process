.PHONY: all
all:
	@more $(MAKEFILE_LIST)

.PHONY: clean
clean:
	$(RM) -r dist result

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: fmt
fmt:
	gofmt -w .
	nixfmt flake.nix

.PHONY: test
test:
	go test -v ./...

.PHONY: release
release:
	goreleaser release --clean --snapshot

.PHONY: derivation
derivation:
	nix build

.PHONY: ci
ci: lint fmt test
	git diff --exit-code
