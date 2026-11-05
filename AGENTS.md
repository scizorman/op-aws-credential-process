# op-aws-credential-process

A `credential_process` helper for AWS CLI. Retrieves AWS credentials from 1Password, performs MFA authentication, and returns temporary credentials.

## Architecture

### External Dependencies

- `op` (1Password CLI) — Used to retrieve credentials. Invoked as an external command.
- AWS STS — Uses Go SDK v2 (`github.com/aws/aws-sdk-go-v2`). No dependency on `aws` CLI.

The 1Password Go SDK's desktop app integration is beta and does not support WSL, so we invoke the `op` command externally.

### credential_process Constraints

`credential_process` is a protocol that returns JSON on stdout. Nothing other than credential JSON may be written to stdout. Error messages and debug logs must go to stderr. Since the caller captures stdin and stderr, interactive input requires opening `/dev/tty` directly.

### Design Principles

**Layer Separation**

Separate the presentation layer (CLI argument parsing, config loading, dependency wiring, stdout output) from domain logic. Convert config values into domain types before passing them to the domain layer.

**Interface Criteria**

Only introduce an interface when the implementation detail is outside the Resolver's concern, or when multiple implementations are realistically expected. Do not introduce interfaces based on speculation about future changes.

**Test Doubles**

Do not use mock generation tools such as mockgen. Write fakes (lightweight working implementations) by hand in `_test.go` files.

### Package Policy

Place files flat in the root package. Split into separate packages only when the code outgrows a single package. Do not use the `internal/` directory.

## Development Commands

Development tools (Go, golangci-lint, nixfmt, goreleaser) are provided by the Nix flake devShell. Do not rely on tools installed outside of it, because their versions may differ.

Inside the devShell (`nix develop` or direnv), run the targets directly. Outside of it (`IN_NIX_SHELL` is unset), prefix every command with `nix develop -c`, e.g. `nix develop -c make ci`. CI runs the same command.

| Target | Description |
|-----------|------|
| `make all` | Show Makefile contents (help) |
| `make clean` | Remove `dist` and `result` |
| `make deps` | `go mod vendor` |
| `make lint` | golangci-lint |
| `make fmt` | `go fmt` + nixfmt |
| `make test` | go test |
| `make release` | goreleaser snapshot release |
| `make derivation` | nix build |
| `make ci` | lint + fmt + test, then fail if the working tree has diffs |
