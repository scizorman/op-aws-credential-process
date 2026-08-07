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
	go fmt ./...
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

vendor/modules.txt: go.mod go.sum
	go mod vendor

.PHONY: ci
ci: lint fmt test
	git diff --exit-code
