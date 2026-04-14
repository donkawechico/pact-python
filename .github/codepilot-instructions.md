# Copilot instructions for pact-python

- Treat `.sync-inputs/pact/` as read-only upstream source of truth.
- Do not edit `.sync-inputs/` or `.sync-metadata/`.
- Only modify `src/pact/`, `tests/`, and small repo metadata files if required.
- Preserve the public pact-python API unless upstream fixtures/spec require otherwise.
- Prefer minimal changes that make upstream fixture tests pass.
- Do not refactor unrelated code.