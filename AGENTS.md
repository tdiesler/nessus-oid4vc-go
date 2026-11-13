# Agent conventions for this repo

Agreements established while bootstrapping this project. Keep this file
current as new conventions get established.

## Working agreement

- Discuss proposed changes before modifying files.
- When working on an issue, discuss the viable implementation options and their
  tradeoffs with the user first, and agree on an approach before implementing it.
  An initial request to work on an issue authorizes investigation and discussion;
  it does not by itself authorize choosing and implementing an approach.
- This discuss-first rule is for substantive work: design/approach choices, new
  abstractions, behavior changes, or anything where a reasonable person could
  disagree on the right shape. It does not apply to trivial, obvious fixes with
  a single reasonable resolution (typos, mislabeled section banners, missing
  doc-convention markers, misplaced test fixtures, grammar nits) — just make
  those and mention what was done.
- In prose, surround em dashes with spaces (`word — word`).
- Treat user suggestions as hypotheses to evaluate, not decisions to affirm
  automatically. Check them against the stated objective, current evidence,
  repository invariants, costs, risks, and plausible alternatives. If a
  suggestion is weak, unnecessary, internally inconsistent, or materially
  inferior to another approach, say so directly, explain why, and recommend
  the stronger option. When a suggestion is reasonable, state the supporting
  rationale and relevant tradeoffs rather than merely agreeing. Optimize for
  correctness and outcomes rather than consensus: respectful disagreement and
  proving either side wrong with evidence are welcome. Do not manufacture
  objections when the evidence supports the proposal.
- Always provide complete, copyable command lines when suggesting test runs.
  Join multiple suggested test runs with `&&` so execution stops on failure.
- Keep `AGENTS.md` focused on durable agent instructions and cross-cutting
  invariants. Document user-facing behavior in Go doc comments and CLI help so
  it is visible alongside the relevant code in the IDE. Avoid duplicating
  behavior descriptions in `AGENTS.md`.
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
- Leave a blank line between code and a following standalone comment, including
  after an opening brace. A comment must not start immediately below a line of code.
- Reuse established variable names consistently when possible.
- Bind helpers to the narrowest useful scope. Prefer private receiver methods
  for helpers belonging to one type; use package functions only for shared
  package-level behavior, and local functions when their use is local.
- Separate stages in multistage functions with a blank line. Start each stage
  with a short, concise line comment naming the next operation. Keep detailed
  explanations for non-obvious behavior.
- Sort functions alphabetically unless logical grouping or lifecycle order is
  clearer for the specific code.
- Keep each type declaration and all of its receiver methods in one source
  file. Do not split methods for the same type across multiple files.
- Organize each source-file type section as follows: a `// TypeName ===...`
  marker, the type definition, `New*` constructors, fluent `With*` methods used
  with those constructors, and then the remaining public receiver methods in a
  meaningful order (usually alphabetical). Follow those with a
  `// Private ---...` marker and the private receiver methods. Keep all methods
  with a receiver together; place receiver-free functions afterward under a
  `// Functions ---...` marker. Repeat this structure for additional types in
  the same file where appropriate.
- Add new `Test*` functions in alphabetical order by name.
- In `*_test.go` files, place all `Test*` functions before private support
  code. Put private (unexported) test structures, fixtures, and helper
  functions below a `// Private ---...` marker. Exported fixtures/constants
  are not private support code: they stay at the top of the file, same as
  any other exported package-level declaration.
- Don't itemize another file's or script's specific details in a doc comment
  (e.g. naming exact resource names a test assumes some other file already
  set up). State what the code does and that it depends on pre-existing
  setup, without restating the setup's specifics — those go stale the moment
  the other file changes, silently. A comment noting the *provenance* of a
  specific value (e.g. "fixed by scripts/vault-setup's client registration"
  next to a literal) is fine; restating a list of facts that live elsewhere
  is not.

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
  Each minor commit requires individual user sign-off; agreeing to work in
  minor steps does not authorize subsequent commits.
- Never `git push` (including force variants) without the user's explicit,
  per-action confirmation in that message. Amending a commit changes the
  local commit only and does not imply permission to push.
- Prefer new commits over amending once a commit has been pushed.
- Commit messages for commits with multiple notable changes: one short
  bullet per point, not prose paragraphs.
  Include a commit body with bullets summarizing material changes and relevant
  operational commands. Do not add build or test commands unless explicitly
  requested.
- Work an issue on its own feature branch using **minor commits**: title
  starts with `--`, e.g. `-- Do this`.
  Omit the issue reference because the feature branch already provides it.
  Start issue titles and commit subject text (after the minor prefix) with a
  capital letter.
- A **major commit** is that feature branch's minor commits squashed into a
  single commit and merged to `main`. Its title is the issue's title
  verbatim plus its number, e.g. `Do stuff (#123)`.
  Use the issue's current title. A major commit is not another commit on the
  feature branch. Refresh `origin/main` before integration and include the
  co-author trailer above. Pushing requires separate explicit authorization.

## Instruction currency

- `AGENTS.md` must describe the current repository state and working agreement.
- Before completing a change, inspect whether it makes information in
  `AGENTS.md` inaccurate or obsolete. If it does, update `AGENTS.md` in the same
  change and flag the update to the user.
- When `AGENTS.md` disagrees with current configuration, executable test
  fixtures, or implementation, flag the discrepancy immediately and correct
  `AGENTS.md` as part of the current work.
- Keep historical experiments, results, conclusions, and completed work in the
  associated issues. Do not duplicate them in `AGENTS.md`.
- Keep only durable rules, current invariants, tracking entry points, and
  startup-discovery instructions here. Obtain dynamic work-item status from
  repository issues.

## Session startup and sources of truth

- At the start of work, inspect the current branch, `HEAD`, `origin/main`, and
  working-tree state. Do not overwrite or include unrelated user changes.
- Distinguish explicitly between `origin/main` (the remote-tracking baseline),
  `HEAD` (the checked-out commit), and the working tree (uncommitted development).
  The locally stored remote-tracking reference may be stale until fetched;
  verify that it is fresh when the current remote state matters.
- Treat current configuration and executable test fixtures as authoritative for
  behavior. Inspect the relevant implementation when semantics are not fully
  captured by those sources.
- Treat issue results as historical observations tied to the commits,
  configuration, and ranges recorded in the issue. Never use them as evidence
  of current behavior without verifying the current checkout.
- Record commit identities for experiments only when the commit is on `main`.
  Feature-branch commit identities are unstable because integration squashes
  them. Before a stable `main` checkpoint exists, record the branch, effective
  configuration, command, UTC range, and result artifacts instead. When a
  stable restoration point is required, arrange an explicitly authorized major
  checkpoint commit on `main` first.
- Before reporting operational facts or estimating runtime, inspect the current
  configuration, relevant fixtures, and implementation rather than relying on
  earlier session context or completed experiment results.

## Project tracking

- Work is broken into GitHub milestones and issues on this repo rather than
  one large change; see the README's Status section.
- GitHub is the canonical Git host and issue tracker. Normal issue and milestone
  management for this repository is authorized; destructive repository, account,
  release, or branch operations still require explicit approval.
- Use milestones and issues to discover active work. Issue bodies and comments
  are the canonical location for experiment definitions, commands, stable `main`
  commit identities, effective configuration, time ranges, results, conclusions,
  and follow-up decisions. Verify implementation claims against the current
  checkout.
- Keep feature and task issue bodies concise. State the intended change and
  acceptance criteria in a few bullets; omit descriptions of the current state
  unless they are necessary to understand the work. Assign every new issue the
  appropriate existing label, such as `feature`, `task`, or `bug`.
