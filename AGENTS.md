# AGENTS.md

## Constraints

- This is an AWS `credential_process` helper. Stdout must contain nothing but the credential JSON; write errors and logs to stderr. The caller captures stdin and stderr, so interactive input (the MFA code) must be read from `/dev/tty`.
- Fetch secrets by invoking the `op` CLI, not the 1Password Go SDK. The SDK's desktop app integration is beta and does not support WSL.

## Conventions

- Add an interface only when it hides a detail outside the credential logic's concern, or when multiple implementations are realistically expected.
- Write test doubles as hand-written fakes in `_test.go` files. Do not use mockgen or other generators.
- Keep all code in the root package. Do not use `internal/`.

## Development

Run tools through the Nix devShell, e.g. `nix develop -c make test`. Verify changes with `nix develop -c make ci`, the same command CI runs. It ends with `git diff --exit-code`, so unstaged changes make it fail.
