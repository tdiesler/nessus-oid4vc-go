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

## Dependency choices

- Use `github.com/hashicorp/vault/api` (stable), not the beta
  `hashicorp/vault-client-go`.
- Hand-roll the SD-JWT VC builder rather than depend on an immature
  third-party SD-JWT VC library. Vault Transit signs remotely, so a
  pluggable `Signer` interface is needed regardless of library choice.

## Testing

- Run plain, fast, in-process unit tests freely.
- Anything that needs a real Vault (e.g. `vault server -dev`), Docker, or
  another live service is not run by the agent — document the manual steps
  (e.g. in the README) and hand verification to the user.

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
