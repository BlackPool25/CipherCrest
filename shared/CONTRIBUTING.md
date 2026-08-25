# CONTRIBUTING — SecureMailScope

## CODEOWNERS

| Path | Owner | Rule |
|------|-------|------|
| `shared/schemas.py` | P1 only | CODEOWNER: ONLY P1 may merge changes to `shared/schemas.py`. Others must open PR and request P1 review. |
| `shared/fixtures/*` | P1 only | CODEOWNER: ONLY P1 may merge changes to `shared/fixtures/*`. Others must open PR and request P1 review. |
| `*` (all other paths) | Any agent | Any contributor may open PR; standard review applies. |

**CODEOWNER enforcement:** `shared/schemas.py` and `fixtures/*` are owned by P1 (TLS/X.509, shared CODEOWNER). Breaking changes require 2-agent ack + version bump + `schemas.json` regen. Day2 00:00 additive-only — new Optional fields only.

## Workflow

- `git pull --rebase` mandatory before push (no merge commits).
- All PRs must pass server-side CI (`.github/workflows/ci.yml`) — Require status checks + Merge queue is authoritative.
- `pre-push` hook (`pytest shared/tests/test_schema.py`) is advisory only (bypassable via `--no-verify`); CI hard fail is required.
- No `pip download` or `docker save` on Day1 — schemas-only bundle.
- Branch protection: Require status checks on `main`.

## Freeze Doctrine

- `shared/schemas.py` freeze at Day2 00:00 additive-only (new Optional fields only); breaking change needs P1 + one other agent ack.

## Freeze Day2 00:00

Day2 00:00 additive-only — breaking change needs 2-agent ack + version bump + schemas.json regen

- `shared/schemas.py` is frozen additive-only from Day2 00:00: only new `Optional` fields with defaults are allowed without version bump.
- Breaking change (rename/remove/required field, type change, tightening `extra='forbid'`) needs 2-agent ack (P1 + one other), version bump in `shared/schemas.py` header and `shared/schemas.json` `version` field, and `schemas.json` regen via `python shared/scripts/gen_schemas_json.py`.
- `shared/fixtures/*` and `shared/schemas.json` remain CODEOWNER P1; CI hard-fails on `ValidationError` if field renamed without bump (see `shared/tests/test_freeze_guard.py::test_breaking_change_fails`).
