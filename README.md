# envctl

[![CI](https://github.com/julienmarie/envctl/actions/workflows/ci.yml/badge.svg)](https://github.com/julienmarie/envctl/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/julienmarie/envctl)](https://github.com/julienmarie/envctl/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`envctl` is a local-first, encrypted secret manager for development workflows.
It keeps one registry of projects, environments, secret names, assignments, and
environment-specific values; injects only the requested values into a child
process; and includes a terminal UI, dotenv import, encrypted portable sync
bundles, and Kubernetes Secret generation.

```console
$ envctl check payments-api dev
Project: payments-api
Environment: dev

DATABASE_URL    resolved
REDIS_URL       resolved
STRIPE_API_KEY  missing
```

> [!IMPORTANT]
> envctl is pre-1.0 software. Encrypted bundle export/import works, but live
> peer-to-peer transport does not. The current `sync pair`, `sync join`,
> `sync now`, and `sync daemon` commands are transport scaffolding, not a
> complete device-pairing protocol. Read [Trusted-device sync](#trusted-device-sync)
> before relying on sync.

## Why envctl?

Developers commonly accumulate `.env` files across repositories, copy secrets
between shell profiles, and lose track of which project needs which value.
envctl centralizes that local workflow without turning secrets into positional
arguments, committed files, or permanently exported shell variables.

- **Local first:** no account, server, or network connection is required.
- **Encrypted at rest:** values and sync operations are encrypted with
  ChaCha20-Poly1305.
- **OS-backed keys:** the master key is stored in the platform keyring when one
  is available, with a restrictive local-file fallback.
- **Environment variants:** one secret name can have different `dev`, `staging`,
  and `prod` values.
- **Explicit project scope:** secrets are injected only when assigned to the
  selected project.
- **Fail-closed execution:** unresolved assigned secrets prevent the child
  process from starting.
- **No secret CLI arguments:** interactive entry uses a hidden prompt; pipelines
  can provide values through standard input.
- **Terminal UI:** navigate projects and environments as a coverage matrix.
- **Portable encrypted sync:** export and idempotently replay operation bundles
  between trusted machines.
- **Kubernetes output:** render or directly apply a namespaced Kubernetes
  `Secret`.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Core model](#core-model)
- [Command reference](#command-reference)
- [Terminal UI](#terminal-ui)
- [Dotenv import](#dotenv-import)
- [Trusted-device sync](#trusted-device-sync)
- [Kubernetes](#kubernetes)
- [Storage and encryption](#storage-and-encryption)
- [Security considerations](#security-considerations)
- [Recipes](#recipes)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)
- [Development](#development)
- [Releases](#releases)

## Installation

Official release archives are built for:

| Operating system | Architecture | Release asset |
| --- | --- | --- |
| macOS | Apple Silicon (`arm64`) | `envctl-VERSION-macos-arm64.tar.gz` |
| macOS | Intel (`x86_64`) | `envctl-VERSION-macos-x86_64.tar.gz` |
| Linux (glibc) | `x86_64` | `envctl-VERSION-linux-x86_64.tar.gz` |
| Linux (glibc) | ARM64 | `envctl-VERSION-linux-arm64.tar.gz` |

Every archive has an adjacent SHA-256 checksum file, and each release includes
an aggregate `SHA256SUMS` file.

### Installer script

Inspect the installer before running it:

```sh
curl -fsSLO https://raw.githubusercontent.com/julienmarie/envctl/main/scripts/install.sh
less install.sh
sh install.sh
```

By default it installs to `~/.local/bin`. Make sure that directory is on your
`PATH`:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Install a specific release or choose another directory:

```sh
sh install.sh --version v0.1.0
sh install.sh --dir /usr/local/bin
```

The equivalent environment variables are `ENVCTL_VERSION` and
`ENVCTL_INSTALL_DIR`.

### Manual installation

Download the archive and matching `.sha256` file from the
[latest release](https://github.com/julienmarie/envctl/releases/latest), then:

```sh
shasum -a 256 -c envctl-0.1.0-macos-arm64.tar.gz.sha256
tar -xzf envctl-0.1.0-macos-arm64.tar.gz
install -m 0755 envctl-0.1.0-macos-arm64/envctl "$HOME/.local/bin/envctl"
envctl --help
```

Replace the filename with the asset for your platform. Linux users can use
`sha256sum -c` instead of `shasum -a 256 -c`.

### Build from source

envctl requires Rust 1.85 or newer because the workspace uses Rust 2024.

```sh
git clone https://github.com/julienmarie/envctl.git
cd envctl
cargo build --release --locked --package envctl-cli
install -m 0755 target/release/envctl "$HOME/.local/bin/envctl"
```

On Linux, a desktop Secret Service implementation is recommended for keyring
storage. Headless systems automatically fall back to a restrictive local key
file when the keyring is unavailable.

## Quick start

Create a project, an environment, and a secret definition:

```sh
envctl project add payments-api
envctl env add dev
envctl secret add DATABASE_URL
envctl secret assign DATABASE_URL payments-api
```

Set the development value. On an interactive terminal envctl displays a hidden
prompt:

```sh
envctl secret set DATABASE_URL dev
```

For automation, pipe the value through standard input:

```sh
printf '%s' 'postgres://localhost/payments_dev' |
  envctl secret set DATABASE_URL dev
```

Check that every assigned secret has a value:

```sh
envctl check payments-api dev
```

Run a command with the resolved environment:

```sh
envctl run payments-api dev -- cargo run
envctl run payments-api dev -- npm run dev
envctl run payments-api dev -- ./scripts/migrate.sh
```

The child receives `DATABASE_URL`; the parent shell does not. If an assigned
secret has no value for `dev`, envctl lists the missing names and does not start
the command.

Open the terminal interface with either:

```sh
envctl
envctl tui
```

## Core model

envctl separates four ideas:

```text
Project ──assigns──> Secret ──has one value per──> Environment
   │                    │                            │
payments-api       DATABASE_URL                    dev
worker             REDIS_URL                       staging
web                STRIPE_API_KEY                  prod
```

- A **project** is an application or workload, such as `payments-api`.
- An **environment** is a deployment context, such as `dev` or `prod`.
- A **secret** is a stable environment-variable name, such as `DATABASE_URL`.
- A **variant** is the value of one secret in one environment.
- An **assignment** connects a secret to every project that requires it.

This model lets `DATABASE_URL` be shared by several projects while retaining a
different value for every environment.

## Command reference

Run `envctl <command> --help` for the authoritative syntax installed with your
version.

### Projects

```sh
envctl project list
envctl project add <name>
envctl project rename <old> <new>
envctl project remove <name> --yes
```

Names must be unique. Removal is destructive and requires `--yes`.

### Environments

```sh
envctl env list
envctl env add <name>
envctl env rename <old> <new>
envctl env remove <name> --yes
```

An environment containing variants cannot be removed unless the destructive
operation is explicitly confirmed.

### Secrets

```sh
envctl secret list
envctl secret add <KEY>
envctl secret rename <OLD_KEY> <NEW_KEY>
envctl secret describe <KEY> [DESCRIPTION]
envctl secret remove <KEY> --yes
```

Set or clear an environment-specific value:

```sh
envctl secret set <KEY> <environment>
envctl secret unset <KEY> <environment>
```

Assign or unassign it from a project:

```sh
envctl secret assign <KEY> <project>
envctl secret unassign <KEY> <project>
```

Secret values are deliberately excluded from positional arguments and listings,
reducing accidental exposure through shell history and process listings.

### Coverage and resolution

Check one project/environment pair:

```sh
envctl check payments-api staging
```

With no arguments, `check` summarizes all projects. Supplying only one argument
is invalid; provide both the project and environment or neither.

Show which assigned names resolve without revealing values:

```sh
envctl resolve payments-api staging
```

Validate before a deployment command without running it:

```sh
envctl run payments-api prod --check
```

### Running commands

```sh
envctl run <project> <environment> -- <program> [arguments...]
```

Always include `--` before the child command. envctl resolves every assigned
secret, adds it to the child environment, forwards the command's exit status,
and never mutates the parent shell.

## Terminal UI

The TUI combines an active project, an active environment, and a coverage
matrix. Every row is a secret; every environment is a column; and each cell
indicates whether a value is available.

| Key | Action |
| --- | --- |
| `j` / `k`, `↓` / `↑` | Move between secrets |
| `h` / `l`, `←` / `→` | Change active environment |
| `Enter` or `v` | Edit the selected environment value |
| `Space` | Assign or unassign the secret from the active project |
| `p` | Switch project |
| `e` | Switch environment |
| `a` | Add a secret |
| `R` | Rename the selected secret |
| `c` | Edit its description |
| `d` | Delete it after confirmation |
| `/` | Search by key or description |
| `f` | Toggle assigned-only/all secrets |
| `r` | Reveal the selected value until selection changes |
| `S` | Show local sync status |
| `Page Up` / `Page Down` | Navigate long lists |
| `Home` / `End` | Jump to the first or last row |
| `?` | Show all bindings |
| `q` | Quit |

Inside project and environment switchers, use `Ctrl-N` to create, `Ctrl-R` to
rename, and `Ctrl-D` to delete.

## Dotenv import

First create the target project and environment, then import:

```sh
envctl project add payments-api
envctl env add dev
envctl import-dotenv payments-api dev .env
```

The import creates missing secret definitions, sets each value for the target
environment, and assigns every imported secret to the project. Existing
variants stop the import unless overwriting is explicitly approved:

```sh
envctl import-dotenv payments-api dev .env --yes
```

Treat the source `.env` file as plaintext secret material. Delete or securely
store it after migration, and never commit it.

## Trusted-device sync

Every local mutation appends an encrypted operation to the local sync log.
`sync export` decrypts those local operations in memory and wraps the complete
portable bundle with a separate 256-bit sync root key. `sync import` decrypts
the bundle, ignores operation IDs already present, applies missing operations in
timestamp order, and re-encrypts them under the receiving machine's local
master key.

### What works today

- Creating and reading a sync root key.
- Exporting all known operations to an authenticated encrypted bundle.
- Importing bundles on a machine with its own independent local master key.
- Idempotently ignoring operations already imported.
- Latest-timestamp-wins handling for concurrent secret variant updates.

### What is not complete

- Live peer discovery or transport.
- Network exchange in `sync now`.
- A background transport loop in `sync daemon`.
- Pairing-code validation or key exchange between `sync pair` and `sync join`.
- Device revocation and automatic sync-key rotation.

### Manual two-machine workflow

On computer A, create the root key once:

```sh
SYNC_KEY="$HOME/.config/envctl/sync-root.key"
envctl sync init --key-file "$SYNC_KEY"
envctl sync export "$HOME/Desktop/envctl-computer-a.bundle" \
  --key-file "$SYNC_KEY"
```

Transfer the bundle and transfer the root key through a separate secure channel.
Do not run `sync init` on computer B: it must receive the exact key created by A.

On B:

```sh
SYNC_KEY="$HOME/.config/envctl/sync-root.key"
envctl sync import "$HOME/Downloads/envctl-computer-a.bundle" \
  --key-file "$SYNC_KEY"
envctl sync export "$HOME/Desktop/envctl-computer-b.bundle" \
  --key-file "$SYNC_KEY"
```

Import B's bundle back on A. Re-importing the same bundle is safe. Export to a
new filename each time because envctl refuses to overwrite an existing bundle.

For several computers, use unique device-and-timestamp filenames and import all
bundles before producing the next export. Keep clocks synchronized because
variant conflict resolution uses operation timestamps. Avoid concurrent
structural changes such as renaming or deleting the same project, environment,
or secret on different computers.

### Sync key handling

- Keep the root key out of the folder or repository used to transport bundles.
- Store it in a password manager or transfer it with an encrypted channel.
- A person with both the key and any historical bundle can decrypt that
  bundle's operation history, including values later deleted from the registry.
- There is currently no automatic rotation command. Treat suspected key
  exposure as compromise of every bundle encrypted with that key.

Inspect local log status with:

```sh
envctl sync status
```

## Kubernetes

Render a Kubernetes Secret without applying it:

```sh
envctl k8s render payments-api prod \
  --name payments-api-secrets \
  --namespace payments
```

Apply it through `kubectl apply -f -`:

```sh
envctl k8s apply payments-api prod \
  --name payments-api-secrets \
  --namespace payments
```

Both commands use the same resolution rules as `envctl run`: every secret
assigned to the project must have a value for the requested environment. The
rendered manifest uses Kubernetes `stringData`, so redirected output contains
plaintext values. Protect generated files and CI logs accordingly.

`k8s apply` requires `kubectl`, a configured context, and authorization to apply
Secrets in the requested namespace.

## Storage and encryption

By default, `store.db` is stored in the platform application-data directory:

| Platform | Typical data directory |
| --- | --- |
| macOS | `~/Library/Application Support/envctl/` |
| Linux | `~/.local/share/envctl/` |

Configuration, device identity, and default sync-key paths use the platform
configuration directory. Exact locations follow the operating system and the
Rust `directories` conventions.

Set `ENVCTL_HOME` to place both data and configuration under an explicit path:

```sh
ENVCTL_HOME="$HOME/.local/share/envctl-isolated" envctl project list
```

This is useful for testing and isolated profiles. It does not guarantee that
the master key is stored inside that directory: envctl still prefers the OS
keyring.

### Local keys

At first use, envctl generates a random 256-bit master key. It attempts to store
that key in the operating system credential store:

- macOS Keychain on macOS.
- Secret Service-compatible keyring on Linux.

When no supported keyring is available, envctl stores a `master-key` fallback
file in its configuration directory with restrictive permissions on Unix.
Secret variants and sync-operation payloads in SQLite are encrypted using
ChaCha20-Poly1305 with a fresh nonce for every value.

### Backups

Do not continuously synchronize a live `store.db` with a general file-sync
service. SQLite files do not support conflict merging, and a copied database
cannot be decrypted without its matching master key. Prefer encrypted sync
bundles for portable backups and machine-to-machine transfer.

## Security considerations

envctl reduces common secret-management mistakes, but it does not create a
complete security boundary.

- Secrets exist in the child process environment after `envctl run` starts.
- Privileged processes, debuggers, crash reporters, `/proc` access where
  permitted, or the child itself may expose them.
- Shell tracing such as `set -x` can expose values piped into commands.
- Redirected Kubernetes manifests and dotenv files are plaintext.
- TUI reveal mode intentionally displays a value on screen.
- Local database deletion is not guaranteed to securely erase historical disk
  blocks, backups, or filesystem snapshots.
- Encrypted bundles preserve operation history, including superseded values.
- Clock manipulation can affect latest-timestamp-wins sync behavior.

Do not use production credentials in examples, issue reports, screenshots, or
test fixtures. See [SECURITY.md](SECURITY.md) for private vulnerability reports.

## Recipes

### Run a development server

```sh
envctl run web dev -- npm run dev
```

### Run a single database migration

```sh
envctl run payments-api staging -- ./bin/migrate up
```

### Require complete coverage in CI

```sh
envctl check worker ci
```

The command exits unsuccessfully when required variants are missing, making it
suitable as a preflight check.

### Share one secret between projects

```sh
envctl secret add INTERNAL_REGISTRY_TOKEN
envctl secret assign INTERNAL_REGISTRY_TOKEN api
envctl secret assign INTERNAL_REGISTRY_TOKEN worker
envctl secret set INTERNAL_REGISTRY_TOKEN dev
```

### Use isolated registries

```sh
ENVCTL_HOME="$HOME/.local/share/envctl-client-a" envctl
ENVCTL_HOME="$HOME/.local/share/envctl-client-b" envctl
```

### Preview a Kubernetes manifest safely

```sh
envctl check payments-api prod
envctl k8s render payments-api prod \
  --name payments-api-secrets \
  --namespace payments
```

The second command prints plaintext secret values. Do not paste its output into
logs or issue reports.

## Troubleshooting

### `Cannot resolve secrets`

At least one assigned secret lacks a value for the selected environment. Run:

```sh
envctl check <project> <environment>
```

Set each missing variant or unassign secrets the project no longer requires.

### `failed to decrypt secret value`

The database and local master key do not match, often because `store.db` was
copied without the corresponding keyring entry or fallback key. Restore the
matching key or import an encrypted sync bundle into a fresh local store.

### Import rejects an existing variant

Review the source dotenv file, then explicitly allow overwrites:

```sh
envctl import-dotenv <project> <environment> .env --yes
```

### Sync bundle already exists

Exports are intentionally non-overwriting. Choose a fresh filename containing a
timestamp or device name.

### Sync bundle cannot be decrypted

Confirm that every computer uses byte-for-byte identical sync root key material.
Do not initialize a separate root key on each machine.

### Linux keyring is unavailable

Start or unlock a Secret Service-compatible keyring. On headless systems envctl
can use its restrictive fallback file; protect the configuration directory with
normal user-only filesystem permissions and include the key in secure backups.

### `kubectl` apply fails

Verify the active context, namespace, RBAC permissions, and coverage:

```sh
kubectl config current-context
envctl check <project> <environment>
```

## Architecture

envctl is a Rust workspace split into focused crates:

| Crate | Responsibility |
| --- | --- |
| `envctl-cli` | Command parsing, user interaction, and orchestration |
| `envctl-core` | Domain types, registry traits, coverage, and resolution |
| `envctl-crypto` | Master-key management and authenticated encryption |
| `envctl-store` | SQLite persistence, migrations, and operation replay |
| `envctl-sync` | Sync identities, keys, and encrypted bundle format |
| `envctl-runner` | Child-process environment injection and exit handling |
| `envctl-tui` | Ratatui-based terminal interface |
| `envctl-k8s` | Kubernetes Secret rendering and `kubectl` integration |

The local execution path is deliberately small:

```text
CLI/TUI → registry lookup → coverage check → decrypt variants
        → construct child environment → execute child process
```

The sync path operates on mutations rather than copying SQLite:

```text
local mutation → encrypted operation log → sync-root-encrypted bundle
               → transfer → idempotent replay → local re-encryption
```

## Development

Install Rust 1.85 or newer and run:

```sh
cargo build --locked
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Launch the development binary against an isolated registry:

```sh
ENVCTL_HOME="$(mktemp -d)" cargo run -p envctl-cli --
```

The release binary is produced with:

```sh
cargo build --release --locked --package envctl-cli
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Never add
real secret values or generated key material to tests.

## Releases

Pushing a `vMAJOR.MINOR.PATCH` tag starts the release workflow. It runs the full
test suite on each native build machine, creates macOS and Linux archives for
both supported architectures, generates SHA-256 checksums, and publishes a
GitHub Release.

The installer downloads only those versioned release assets and verifies the
matching checksum before installing `envctl`.

## Roadmap

- Authenticated device pairing with actual key exchange.
- A transport backend for `sync now` and `sync daemon`.
- Device inventory, revocation, and sync-key rotation.
- Streaming dotenv import to avoid plaintext temporary files.
- Additional package-manager distribution where maintainable.
- A documented database and bundle migration policy before 1.0.

## License

envctl is available under the [MIT License](LICENSE).
