# op-aws-credential-process

## Constraints

- Write only the credential JSON to stdout and send errors and logs to stderr, because this is an AWS `credential_process` helper and the caller parses stdout. Read interactive input such as the MFA code from `/dev/tty`, since the caller captures stdin and stderr.
- Fetch secrets by invoking the `op` CLI. The 1Password Go SDK's desktop app integration is beta and does not support WSL.

## Conventions

- Add an interface only when it hides a detail outside the credential logic's concern, or when multiple implementations are realistically expected.
- Write test doubles as hand-written fakes in `_test.go` files rather than generated mocks.
- Keep code flat in the root package. If it outgrows one package, split it into a sibling package rather than `internal/`.

## Development

Run tools through the Nix devShell, e.g. `nix develop -c make test`. Verify changes with `nix develop -c make ci`, the same command CI runs. It ends with `git diff --exit-code`, so stage your changes before running it.
