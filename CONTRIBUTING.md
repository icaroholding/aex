# Contributing to AEX

Thank you for considering a contribution. AEX is an open protocol — the more implementations and eyes it gets, the stronger the standard becomes.

## TL;DR

1. Fork, branch from `master`.
2. `git commit -s -m "..."` (the `-s` is required — see [Developer Certificate of Origin](#developer-certificate-of-origin) below).
3. Make sure `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test --workspace`, and the SDK tests all pass locally.
4. Open a PR against `master`. Fill in the template.

## Development environment

### Prerequisites

- Rust stable (managed via [`rustup`](https://rustup.rs/))
- Node 20+ (`nvm install 20`)
- Python 3.10+
- Docker (for the Postgres test instance)
- `cargo-nextest` recommended (`cargo install cargo-nextest`)

### First build

```bash
git clone https://github.com/icaroholding/aex
cd aex

# One-shot dev setup (activates git hooks; see "Git hooks" below).
scripts/setup-dev.sh

# Rust workspace
cargo build --workspace

# Python SDK
cd packages/sdk-python && pip install -e ".[dev]" && cd ../..

# TypeScript SDK + MCP server
cd packages/sdk-typescript && npm install && npm run build && cd ../..
cd packages/mcp-server && npm install && npm run build && cd ../..

# Web (landing + dashboard)
cd web && npm install && npm run build && cd ..
```

### Running the test suite

```bash
# Postgres for integration tests
docker compose -f deploy/docker-compose.dev.yml up -d

# Full Rust suite
DATABASE_URL=postgres://aex:aex_dev@localhost:5432/aex cargo test --workspace

# Python
cd packages/sdk-python && pytest -q

# TypeScript
cd packages/sdk-typescript && npm test
cd packages/mcp-server && npm run build  # no runtime tests yet
```

## Code style

- **Rust:** `cargo fmt` is enforced in CI. `cargo clippy -- -D warnings` must pass. Prefer `thiserror` for library errors, `anyhow` only in binaries.
- **TypeScript:** Prettier + ESLint, both enforced. No `any` without a comment explaining why.
- **Python:** Black formatting + ruff linting. Type hints on all public APIs.
- **Commits:** imperative mood, ≤72-char summary, body wraps at 80 (`feat: add sender-side scanner hook`).

We use [conventional commits](https://www.conventionalcommits.org/) prefixes: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`, `ci:`, `build:`.

## Git hooks

The repository ships with two opt-in hooks under [`.githooks/`](.githooks/):

- **`pre-commit`** — runs `cargo fmt --all -- --check` only when staged
  changes touch Rust files. Fast (< 2s on a warm cache); designed to
  run on every commit.
- **`pre-push`** — runs the full local equivalent of the CI Rust job:
  `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, and `cargo test --workspace --exclude aex-control-plane`.
  Total runtime ~30s-2min depending on cache.

Activate them in your clone:

```bash
scripts/setup-dev.sh
# equivalent to: git config core.hooksPath .githooks
```

The hooks are local-only — they live in your clone, never run on
GitHub. They exist to catch the same failures CI would catch, before
you push. Bypass once with `--no-verify` when needed (e.g. CI
debugging, intentional fmt-skip on docs-only commits).

## Protocol changes vs implementation changes

AEX is a protocol first, a set of implementations second. If your
change touches the wire format:

1. Open a discussion issue first; describe motivation, proposed
   bytes, and the backwards-compatibility story.
2. Update [`docs/protocol-v2.md`](docs/protocol-v2.md) in the same PR
   as the implementation change. (Wire v1 is frozen — only the
   sunset path documented in
   [ADR-0043](docs/decisions/0043-capability-negotiation-dual-wire.md)
   applies to it.)
3. Add a corresponding ADR under [`docs/decisions/`](docs/decisions/)
   if the change has long-term architectural implications.
4. Add a conformance test in
   [`crates/aex-conformance`](crates/aex-conformance) so the change
   is verifiable across implementations.

Implementation-only changes (optimisations, refactors, new scanners)
can go straight to a PR.

## Developer Certificate of Origin

Every commit must be signed off with the DCO. This is a lightweight promise that you wrote the code or have the right to submit it under the project's license. No paperwork, no corporate CLA.

```bash
git commit -s -m "feat: add policy hook"
```

The `-s` appends a `Signed-off-by:` trailer using your `git config user.name` and `user.email`. The full text of the DCO is at [developercertificate.org](https://developercertificate.org).

A GitHub App enforces DCO on every PR. Missing sign-off = PR blocked, fix by rebasing and re-signing.

## Pull request process

1. **Keep PRs focused.** One change, one PR. Refactors separate from features.
2. **Update docs.** If you change wire format or public API, update the matching doc in `docs/`.
3. **Tests are required** for any behavior change. The CI runs them on Linux + macOS.
4. **Breaking changes** (wire format, public Rust API, SDK function signatures) require a `BREAKING CHANGE:` footer in the commit message and a bump to the major version.

A maintainer will review within 72 hours. After approval, squash-and-merge into `master`.

## Reporting bugs

Use the GitHub issue tracker with the `bug` template. Include:
- AEX version (`cargo pkgid aex-core`)
- OS + architecture
- Minimal reproduction

For **security** reports, see [SECURITY.md](SECURITY.md) — do not open public issues for vulnerabilities.

## Feature requests

Open an issue with the `enhancement` template. We triage weekly.

## Code of conduct

We follow the [Contributor Covenant](CODE_OF_CONDUCT.md). Be respectful, be curious, be patient with beginners. Harassment of any kind results in a ban.

## License

By contributing, you agree that your contribution is licensed under Apache-2.0 (or BSL-1.1 for `aex-control-plane` modifications). The DCO sign-off is your statement that you have the right to submit under these terms.

---

Questions? Open a discussion or reach out on the community channel (link on the repo README).
