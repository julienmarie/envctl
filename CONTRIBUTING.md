# Contributing to envctl

Thank you for helping improve envctl.

## Development setup

Install Rust 1.85 or newer, clone the repository, and run:

```sh
cargo build --locked
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Use an isolated store while developing:

```sh
ENVCTL_HOME="$(mktemp -d)" cargo run -p envctl-cli -- project list
```

Never commit a test database, `.env` file, master key, sync root key, or sync
bundle. Use clearly fake credentials in tests and documentation.

## Pull requests

Keep changes focused, add tests for behavior changes, and update the README when
the command-line interface or security model changes. Explain user-visible
behavior and any migration requirements in the pull request description.

## Releases

Releases are generated from signed or annotated `vMAJOR.MINOR.PATCH` tags. The
release workflow builds native archives for supported macOS and Linux
architectures, generates SHA-256 checksums, and publishes a GitHub Release.

For security reports, follow [SECURITY.md](SECURITY.md) instead of opening a
public issue.
