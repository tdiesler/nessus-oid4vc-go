# Agent conventions for this repo

Agreements established while bootstrapping this project. Keep this file
current as new conventions get established.

## Architecture decisions

- The OID4VCI/OID4VP protocol surface is a standalone Go service, not a
  Vault plugin. Plugins can only answer `/v1/<mount>/<path>` requests from
  clients holding a Vault token; wallets need public OAuth2/OIDC-shaped
  HTTP endpoints, which plugins can't expose.
- Vault stays unmodified for this POC: it's used as the auth backend
  (OIDC/userpass → Identity entities), the claims source (KV v2), and the
  signer (Transit) — the issuer service never holds a private key.
- Confirmed POC defaults: **SD-JWT VC** credential format,
  **pre-authorized code** issuance flow, **1:1** Vault Identity entity to
  credential subject mapping.
- Wallets only ever talk to our issuer service — never directly to Vault,
  even where Vault exposes a usable raw endpoint (e.g. its own OIDC Provider,
  or `sys/wrapping/unwrap`). Reasons: (1) Vault has no concept of OID4VCI
  credentials, the `pre-authorized_code` grant, or issuer metadata — those
  only exist in our service, so a generic wallet has to talk to us for them
  regardless; (2) Vault is normally an internal/sensitive system and
  shouldn't be made directly reachable by arbitrary public wallets just
  because one grant type happens to be implementable that way. Even flows
  we could technically proxy straight through to Vault (e.g. Authorization
  Code against Vault's OIDC Provider) stay fronted by our service, so
  wallets see one consistent contract.

## Dependency choices

- Use `github.com/hashicorp/vault/api` (stable), not the beta
  `hashicorp/vault-client-go`.
- Hand-roll the SD-JWT VC builder rather than depend on an immature
  third-party SD-JWT VC library. Vault Transit signs remotely, so a
  pluggable `Signer` interface is needed regardless of library choice.

## Go conventions

- Every struct `Foo` gets a constructor `NewFoo(...)`. For services, it
  returns `(*Foo, error)` and validates required fields; for plain value
  types, it returns `Foo` (no error) when there's nothing to validate.
  Callers — including our own code within the package — always go through
  `NewFoo`, never a `Foo{...}` struct literal.

## Testing

- No Vault mocks/fakes: confidence in "this works against Vault" only comes
  from actually talking to Vault. Any test for functionality we claim to
  support (KV reads, Transit signing, identity/entity lookups, token
  issuance, ...) is an integration test that runs against a real Vault —
  the local dev instance (`scripts/vault-setup`'s target), not an in-memory
  fake implementing the client interface.
- Keep integration tests from stepping on each other without relying on
  Vault namespaces (OSS/OpenBao doesn't have them): each test uses its own
  uniquely-named entity/KV path (e.g. derived from `t.Name()` or a random
  suffix) and tears it down via `t.Cleanup`, rather than depending on
  `scripts/vault-setup`'s full reset.
- Plain, fast, in-process unit tests with no external dependency (e.g. the
  pre-authorized-code store's expiry/single-use logic) stay as such — not
  everything needs Vault.
- The agent may access the local dev Vault instance directly (CLI, curl, Go
  tests) and is expected to for anything above — be practical about it,
  including the token overhead of doing so. Flag it rather than dumping a
  verbose response when output would be expensive to process. Docker,
  Kubernetes, or any other live/deployed service beyond this local dev
  Vault stays off-limits per the user's global instructions.

## Git

- Never `git commit` (including amending) unless explicitly told to in that
  message. Finishing a piece of work does not imply permission to commit it.
- Never `git push` (including force variants) without the user's explicit,
  per-action confirmation in that message. Amending a commit changes the
  local commit only and does not imply permission to push.
- Prefer new commits over amending once a commit has been pushed.
- Commit messages for commits with multiple notable changes: one short
  bullet per point, not prose paragraphs.
- Work an issue on its own feature branch using **minor commits**: title
  starts with `--`, e.g. `-- do this`.
- A **major commit** is that feature branch's minor commits squashed into a
  single commit and merged to `main`. Its title is the issue's title
  verbatim plus its number, e.g. `Do stuff (#123)`.

## Project tracking

- Work is broken into GitHub milestones and issues on this repo rather than
  one large change; see the README's Status section.
