# AEX — repo guidance

Public reference implementation of AEX (Agent Exchange Protocol).

## Build whole workspace
```
cargo check --workspace
```

## Integration tests (requires Postgres)
```
docker compose -f deploy/docker-compose.dev.yml up -d
DATABASE_URL=postgres://aex:aex_dev@localhost:5432/aex cargo test --workspace
```

## Crates
- `aex-core` — shared types, traits, wire formats, errors
- `aex-identity` — SpizeNativeProvider (Ed25519), EtereCitizen provider
- `aex-control-plane` — registry + ticket issuer + audit anchor (BSL-1.1)
- `aex-audit` — Merkle-chained local audit log + Rekor trait
- `aex-scanner` — size / MIME / YARA / regex pipeline
- `aex-policy` — pre-send + post-scan trait + tier default
- `aex-tunnel` — Cloudflare tunnel orchestration
- `aex-billing` — billing provider trait (skeleton; real Stripe in spize-enterprise)

## Packages
- `packages/sdk-python` — PyPI `aex-sdk`, imported as `aex_sdk`
- `packages/sdk-typescript` — npm `@aexproto/sdk`
- `packages/mcp-server` — npm `@aexproto/mcp-server`

## Related
- Spize Desktop (private): https://github.com/icaroholding/aex-desktop
- Spize Enterprise (private): https://github.com/icaroholding/aex-enterprise
- EtereCitizen (public): https://github.com/icaroholding/EtereCitizen

## Identity format

Two identity-format lines coexist during the v1→v2 grace window
(ADR-0043):

- **Wire v1 (legacy)**: `spize:org/name:fingerprint`. Held stable for the
  duration of the 6-month grace window per ADR-0043. Still produced by
  `aex_core::wire::*_bytes` functions (prefix `spize-*:v1`).
- **Wire v2**: W3C DID URI `did:method:method-specific-id[#fragment]`
  (ADR-0041). Produced by `aex_core::wire_v2::*_bytes_v2` (prefix
  `aex-*:v2`). Methods supported at GA: `did:spize`, `did:web`, `did:ethr`,
  `did:key` (ADR-0047).

The wire-format prefix is no longer brand-tied — ADR-0042 supersedes
the previous "held stable for compatibility" stance.
