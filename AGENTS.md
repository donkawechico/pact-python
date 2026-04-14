# PACT sync repair instructions

These instructions apply specifically to automated sync PRs generated from upstream PACT changes.

## Goal

Update `pact-python` so it conforms to the upstream PACT snapshot and fixture suite referenced in the sync PR.

## Source of truth

- The upstream snapshot in `.sync-inputs/pact/` is read-only source of truth.
- The generated PR body contains the upstream repo, SHA, changed fixture/spec paths, and pytest summary.

## Scope

- Modify only `src/pact/`, `tests/`, and minimal repo metadata when required.
- Do not edit `.sync-inputs/` or `.sync-metadata/`.
- Keep changes narrowly scoped to the upstream fixture/spec drift in the PR.

## Repair strategy

- Start from the failing pytest summary in the PR body.
- Prefer the smallest implementation change that makes the upstream fixture tests pass.
- Preserve the existing public API unless the upstream PACT fixtures/spec require a breaking change.
- Do not widen scope into unrelated refactors.

## Validation

- Run the existing test suite.
- Ensure fixes satisfy the upstream SHA referenced by the sync PR.